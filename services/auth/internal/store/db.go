package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type User struct {
	ID                 uuid.UUID  `json:"id"`
	Username           string     `json:"username"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	PasswordHash       string     `json:"-"`
	MFASecretEnc       []byte     `json:"-"`
	MFAEnabled         bool       `json:"mfa_enabled"`
	Status             string     `json:"status"`
	AuthSource         string     `json:"auth_source"`
	MustChangePassword bool       `json:"must_change_password"`
	FailedLoginCount   int        `json:"-"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	Roles              []string   `json:"roles,omitempty"`
	Permissions        []string   `json:"permissions,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
}

type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type AuditEvent struct {
	ID           uuid.UUID      `json:"id"`
	TS           time.Time      `json:"ts"`
	ActorID      *uuid.UUID     `json:"actor_id,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	IP           string         `json:"ip"`
	UserAgent    string         `json:"user_agent"`
	Payload      map[string]any `json:"payload"`
	PrevHash     string         `json:"prev_hash"`
	Hash         string         `json:"hash"`
}

type DB struct {
	Pool *pgxpool.Pool
}

func Connect(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

func (db *DB) Close() {
	db.Pool.Close()
}

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash,
		&u.MFASecretEnc, &u.MFAEnabled, &u.Status, &u.AuthSource,
		&u.MustChangePassword, &u.FailedLoginCount, &u.LockedUntil,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
	)
	return u, err
}

const userCols = `id, username, email, display_name, password_hash, mfa_secret_enc,
	mfa_enabled, status, auth_source, must_change_password, failed_login_count,
	locked_until, last_login_at, created_at, updated_at, created_by`

func (db *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (db *DB) GetUserByUsername(ctx context.Context, username string) (User, error) {
	u, err := scanUser(db.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, username))
	if err != nil {
		return u, err
	}
	return db.attachRoles(ctx, u)
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (User, error) {
	u, err := scanUser(db.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(email)=lower($1)`, email))
	if err != nil {
		return u, err
	}
	return db.attachRoles(ctx, u)
}

func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	u, err := scanUser(db.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return u, err
	}
	return db.attachRoles(ctx, u)
}

func (db *DB) attachRoles(ctx context.Context, u User) (User, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT r.name FROM roles r
		JOIN user_role_bindings urb ON urb.role_id = r.id
		WHERE urb.user_id = $1 ORDER BY r.name`, u.ID)
	if err != nil {
		return u, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return u, err
		}
		u.Roles = append(u.Roles, name)
	}
	perms, err := db.PermissionsForUser(ctx, u.ID)
	if err != nil {
		return u, err
	}
	u.Permissions = perms
	tags, err := db.UserTags(ctx, u.ID)
	if err != nil {
		return u, err
	}
	u.Tags = tags
	return u, rows.Err()
}

func (db *DB) UserTags(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `SELECT tag FROM user_tags WHERE user_id=$1 ORDER BY tag`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []string{}
	}
	return out, rows.Err()
}

func (db *DB) SetUserTags(ctx context.Context, userID uuid.UUID, tags []string) error {
	seen := map[string]struct{}{}
	var norm []string
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		norm = append(norm, t)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM user_tags WHERE user_id=$1`, userID); err != nil {
		return err
	}
	for _, t := range norm {
		if _, err := tx.Exec(ctx, `INSERT INTO user_tags (user_id, tag) VALUES ($1,$2)`, userID, t); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (db *DB) PermissionsForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT p.name FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_role_bindings urb ON urb.role_id = rp.role_id
		WHERE urb.user_id = $1 ORDER BY p.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.Pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		u, err = db.attachRoles(ctx, u)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (db *DB) CreateUser(ctx context.Context, u User, roleNames []string) (User, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, username, email, display_name, password_hash, mfa_secret_enc,
			mfa_enabled, status, auth_source, must_change_password, failed_login_count,
			locked_until, last_login_at, created_at, updated_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		u.ID, u.Username, u.Email, u.DisplayName, u.PasswordHash, u.MFASecretEnc,
		u.MFAEnabled, u.Status, u.AuthSource, u.MustChangePassword, u.FailedLoginCount,
		u.LockedUntil, u.LastLoginAt, u.CreatedAt, u.UpdatedAt, u.CreatedBy,
	)
	if err != nil {
		return User{}, err
	}
	if err := setUserRolesTx(ctx, tx, u.ID, roleNames); err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return db.GetUserByID(ctx, u.ID)
}

func setUserRolesTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, roleNames []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_role_bindings WHERE user_id=$1`, userID); err != nil {
		return err
	}
	for _, name := range roleNames {
		tag, err := tx.Exec(ctx, `
			INSERT INTO user_role_bindings (user_id, role_id)
			SELECT $1, id FROM roles WHERE name=$2`, userID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
	}
	return nil
}

func (db *DB) UpdateUser(ctx context.Context, u User, roleNames *[]string) (User, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE users SET email=$2, display_name=$3, password_hash=$4, mfa_secret_enc=$5,
			mfa_enabled=$6, status=$7, must_change_password=$8, failed_login_count=$9,
			locked_until=$10, last_login_at=$11, updated_at=$12
		WHERE id=$1`,
		u.ID, u.Email, u.DisplayName, u.PasswordHash, u.MFASecretEnc,
		u.MFAEnabled, u.Status, u.MustChangePassword, u.FailedLoginCount,
		u.LockedUntil, u.LastLoginAt, u.UpdatedAt,
	)
	if err != nil {
		return User{}, err
	}
	if roleNames != nil {
		if err := setUserRolesTx(ctx, tx, u.ID, *roleNames); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return db.GetUserByID(ctx, u.ID)
}

func (db *DB) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := db.Pool.Query(ctx, `SELECT id, name, description FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (db *DB) LatestAuditHash(ctx context.Context) (string, error) {
	var hash string
	err := db.Pool.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY ts DESC, id DESC LIMIT 1`).Scan(&hash)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return hash, err
}

func (db *DB) InsertAudit(ctx context.Context, e AuditEvent) error {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, ts, actor_id, action, resource_type, resource_id, ip, user_agent, payload, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		e.ID, e.TS, e.ActorID, e.Action, e.ResourceType, e.ResourceID, e.IP, e.UserAgent, payload, e.PrevHash, e.Hash,
	)
	return err
}

type AuditFilter struct {
	ActorID     *uuid.UUID
	Action      string
	From        *time.Time
	To          *time.Time
	Q           string
	SearchField string // all|action|actor_id|resource_type|resource_id|ip|user_agent
	Limit       int
	Offset      int
}

func (db *DB) buildAuditWhere(f AuditFilter) (string, []any, int) {
	q := ` WHERE 1=1`
	args := []any{}
	i := 1
	if f.ActorID != nil {
		q += ` AND actor_id=$` + itoa(i)
		args = append(args, *f.ActorID)
		i++
	}
	if f.Action != "" {
		q += ` AND action=$` + itoa(i)
		args = append(args, f.Action)
		i++
	}
	if f.From != nil {
		q += ` AND ts>=$` + itoa(i)
		args = append(args, *f.From)
		i++
	}
	if f.To != nil {
		q += ` AND ts<=$` + itoa(i)
		args = append(args, *f.To)
		i++
	}
	if f.Q != "" {
		like := "%" + f.Q + "%"
		field := f.SearchField
		if field == "" {
			field = "all"
		}
		switch field {
		case "action":
			q += ` AND action ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		case "actor_id":
			q += ` AND actor_id::text ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		case "resource_type":
			q += ` AND resource_type ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		case "resource_id":
			q += ` AND resource_id ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		case "ip":
			q += ` AND ip ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		case "user_agent":
			q += ` AND user_agent ILIKE $` + itoa(i)
			args = append(args, like)
			i++
		default:
			q += ` AND (
				action ILIKE $` + itoa(i) + ` OR
				COALESCE(actor_id::text,'') ILIKE $` + itoa(i) + ` OR
				resource_type ILIKE $` + itoa(i) + ` OR
				resource_id ILIKE $` + itoa(i) + ` OR
				ip ILIKE $` + itoa(i) + ` OR
				user_agent ILIKE $` + itoa(i) + ` OR
				payload::text ILIKE $` + itoa(i) + `
			)`
			args = append(args, like)
			i++
		}
	}
	return q, args, i
}

func (db *DB) CountAudit(ctx context.Context, f AuditFilter) (int, error) {
	where, args, _ := db.buildAuditWhere(f)
	var n int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&n)
	return n, err
}

func (db *DB) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where, args, i := db.buildAuditWhere(f)
	q := `SELECT id, ts, actor_id, action, resource_type, resource_id, ip, user_agent, payload, prev_hash, hash
		FROM audit_events` + where + ` ORDER BY ts DESC, id DESC LIMIT $` + itoa(i) + ` OFFSET $` + itoa(i+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorID, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.IP, &e.UserAgent, &e.Payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}
