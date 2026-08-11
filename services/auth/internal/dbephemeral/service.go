package dbephemeral

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db     *store.DB
	env    *crypto.Envelope
	assets *assets.Service
	aud    *audit.Service
	sess   *sessionsvc.Service
}

func New(db *store.DB, env *crypto.Envelope, assetsSvc *assets.Service, aud *audit.Service, sess *sessionsvc.Service) *Service {
	return &Service{db: db, env: env, assets: assetsSvc, aud: aud, sess: sess}
}

type RoleInfo struct {
	RoleName  string `json:"role_name"`
	Privilege string `json:"privilege"`
	Status    string `json:"status"`
}

// Ensure returns TargetCreds for the ephemeral role (creating it if needed).
// Bootstrap uses vault account credentials.
func (s *Service) Ensure(ctx context.Context, sessionID uuid.UUID, vault assets.TargetCreds, privilege string) (assets.TargetCreds, RoleInfo, error) {
	if privilege != "readwrite" {
		privilege = "readonly"
	}
	proto := vault.Asset.Protocol
	if proto != "postgres" && proto != "mysql" {
		return assets.TargetCreds{}, RoleInfo{}, fmt.Errorf("ephemeral roles only for postgres/mysql")
	}

	var existing RoleInfo
	var secretEnc []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT role_name, privilege, status, secret_enc FROM db_session_roles WHERE session_id=$1`, sessionID).
		Scan(&existing.RoleName, &existing.Privilege, &existing.Status, &secretEnc)
	if err == nil && existing.Status == "active" && len(secretEnc) > 0 {
		plain, derr := s.env.Decrypt(secretEnc)
		if derr != nil {
			return assets.TargetCreds{}, RoleInfo{}, derr
		}
		out := vault
		out.Account.Username = existing.RoleName
		out.Secret = string(plain)
		out.AuthMethod = "password"
		return out, existing, nil
	}

	roleName := roleNameFor(sessionID)
	pwd, err := randomPassword()
	if err != nil {
		return assets.TargetCreds{}, RoleInfo{}, err
	}
	enc, err := s.env.Encrypt([]byte(pwd))
	if err != nil {
		return assets.TargetCreds{}, RoleInfo{}, err
	}

	switch proto {
	case "postgres":
		if err := createPostgresRole(ctx, vault, roleName, pwd, privilege); err != nil {
			_ = s.recordFailed(ctx, sessionID, vault, roleName, privilege, enc, err)
			return assets.TargetCreds{}, RoleInfo{}, fmt.Errorf("create ephemeral role: %w", err)
		}
	case "mysql":
		if err := createMySQLRole(ctx, vault, roleName, pwd, privilege); err != nil {
			_ = s.recordFailed(ctx, sessionID, vault, roleName, privilege, enc, err)
			return assets.TargetCreds{}, RoleInfo{}, fmt.Errorf("create ephemeral role: %w", err)
		}
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO db_session_roles
			(session_id, asset_id, account_id, protocol, role_name, privilege, secret_enc, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active',NOW())
		ON CONFLICT (session_id) DO UPDATE SET
			role_name=EXCLUDED.role_name, privilege=EXCLUDED.privilege, secret_enc=EXCLUDED.secret_enc,
			status='active', last_error='', dropped_at=NULL, created_at=NOW()`,
		sessionID, vault.Asset.ID, vault.Account.ID, proto, roleName, privilege, enc)
	if err != nil {
		_ = dropRemote(ctx, vault, roleName)
		return assets.TargetCreds{}, RoleInfo{}, err
	}

	info := RoleInfo{RoleName: roleName, Privilege: privilege, Status: "active"}
	_ = s.sess.AddEvent(ctx, sessionID, "db_role.created", map[string]any{
		"role": roleName, "privilege": privilege, "protocol": proto,
	})
	_ = s.aud.Record(ctx, nil, "session.db_role.created", "session", sessionID.String(), "", "dbephemeral", map[string]any{
		"role": roleName, "privilege": privilege, "protocol": proto, "asset": vault.Asset.Name,
	})

	out := vault
	out.Account.Username = roleName
	out.Secret = pwd
	out.AuthMethod = "password"
	return out, info, nil
}

// Drop removes the ephemeral role on the target DB (best-effort).
func (s *Service) Drop(ctx context.Context, sessionID uuid.UUID) {
	var roleName, proto, status string
	var assetID, accountID uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `
		SELECT role_name, protocol, status, asset_id, account_id
		FROM db_session_roles WHERE session_id=$1`, sessionID).
		Scan(&roleName, &proto, &status, &assetID, &accountID)
	if err != nil || status != "active" {
		return
	}
	creds, err := s.assets.GetTargetCreds(ctx, assetID, accountID)
	if err != nil {
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE db_session_roles SET last_error=$2 WHERE session_id=$1`, sessionID, truncate(err.Error(), 400))
		return
	}
	if err := dropRemote(ctx, creds, roleName); err != nil {
		slog.Warn("ephemeral drop failed", "session", sessionID, "role", roleName, "err", err)
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE db_session_roles SET last_error=$2 WHERE session_id=$1`, sessionID, truncate(err.Error(), 400))
		// still mark dropped so we don't retry forever on permanent errors
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE db_session_roles SET status='dropped', dropped_at=NOW() WHERE session_id=$1`, sessionID)
	_ = s.sess.AddEvent(ctx, sessionID, "db_role.dropped", map[string]any{"role": roleName})
	_ = s.aud.Record(ctx, nil, "session.db_role.dropped", "session", sessionID.String(), "", "dbephemeral", map[string]any{
		"role": roleName, "protocol": proto,
	})
}

func (s *Service) GetInfo(ctx context.Context, sessionID uuid.UUID) (RoleInfo, bool) {
	var info RoleInfo
	err := s.db.Pool.QueryRow(ctx, `
		SELECT role_name, privilege, status FROM db_session_roles WHERE session_id=$1`, sessionID).
		Scan(&info.RoleName, &info.Privilege, &info.Status)
	if err != nil {
		return RoleInfo{}, false
	}
	return info, true
}

func (s *Service) recordFailed(ctx context.Context, sessionID uuid.UUID, vault assets.TargetCreds, role, priv string, enc []byte, createErr error) error {
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO db_session_roles
			(session_id, asset_id, account_id, protocol, role_name, privilege, secret_enc, status, last_error, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'failed',$8,NOW())
		ON CONFLICT (session_id) DO UPDATE SET status='failed', last_error=EXCLUDED.last_error`,
		sessionID, vault.Asset.ID, vault.Account.ID, vault.Asset.Protocol, role, priv, enc, truncate(createErr.Error(), 400))
	return err
}

func roleNameFor(id uuid.UUID) string {
	h := strings.ReplaceAll(id.String(), "-", "")
	if len(h) > 12 {
		h = h[:12]
	}
	return "kp_" + h
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func createPostgresRole(ctx context.Context, vault assets.TargetCreds, role, pwd, privilege string) error {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
		urlUser(vault.Account.Username), urlUser(vault.Secret), vault.Asset.Address, vault.Asset.Port)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("bootstrap dial: %w", err)
	}
	defer conn.Close(ctx)

	until := time.Now().UTC().Add(8 * time.Hour).Format(time.RFC3339)
	ident := pgQuoteIdent(role)
	stmts := []string{
		fmt.Sprintf(`CREATE ROLE %s WITH LOGIN PASSWORD %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT VALID UNTIL %s`,
			ident, pgQuoteLiteral(pwd), pgQuoteLiteral(until)),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE postgres TO %s`, ident),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, ident),
	}
	if privilege == "readwrite" {
		stmts = append(stmts,
			fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s`, ident),
			fmt.Sprintf(`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %s`, ident),
			fmt.Sprintf(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s`, ident),
		)
	} else {
		stmts = append(stmts,
			fmt.Sprintf(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s`, ident),
			fmt.Sprintf(`GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO %s`, ident),
			fmt.Sprintf(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO %s`, ident),
		)
	}
	for _, q := range stmts {
		if _, err := conn.Exec(ctx, q); err != nil {
			_ = dropPostgresRole(ctx, conn, role)
			return err
		}
	}
	return nil
}

func createMySQLRole(ctx context.Context, vault assets.TargetCreds, role, pwd, privilege string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&timeout=15s&multiStatements=true",
		vault.Account.Username, vault.Secret, vault.Asset.Address, vault.Asset.Port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetConnMaxLifetime(30 * time.Second)

	u := mysqlQuoteIdent(role)
	// host '%' for wire/proxy clients
	create := fmt.Sprintf("CREATE USER %s@'%%' IDENTIFIED BY %s", u, mysqlQuoteLiteral(pwd))
	if _, err := db.ExecContext(ctx, create); err != nil {
		return err
	}
	var grant string
	if privilege == "readwrite" {
		grant = fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO %s@'%%'", u)
	} else {
		grant = fmt.Sprintf("GRANT SELECT ON *.* TO %s@'%%'", u)
	}
	if _, err := db.ExecContext(ctx, grant); err != nil {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s@'%%'", u))
		return err
	}
	_, _ = db.ExecContext(ctx, "FLUSH PRIVILEGES")
	return nil
}

func dropRemote(ctx context.Context, vault assets.TargetCreds, role string) error {
	switch vault.Asset.Protocol {
	case "postgres":
		dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
			urlUser(vault.Account.Username), urlUser(vault.Secret), vault.Asset.Address, vault.Asset.Port)
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		return dropPostgresRole(ctx, conn, role)
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?parseTime=true&timeout=15s",
			vault.Account.Username, vault.Secret, vault.Asset.Address, vault.Asset.Port)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return err
		}
		defer db.Close()
		u := mysqlQuoteIdent(role)
		_, err = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s@'%%'", u))
		return err
	default:
		return nil
	}
}

func dropPostgresRole(ctx context.Context, conn *pgx.Conn, role string) error {
	ident := pgQuoteIdent(role)
	// terminate active sessions of the role
	_, _ = conn.Exec(ctx, `
		SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE usename = $1 AND pid <> pg_backend_pid()`, role)
	_, _ = conn.Exec(ctx, fmt.Sprintf(`REASSIGN OWNED BY %s TO CURRENT_USER`, ident))
	_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %s`, ident))
	_, err := conn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, ident))
	if err != nil {
		// ignore undefined_object
		if pgerr, ok := err.(*pgconn.PgError); ok && pgerr.Code == "42704" {
			return nil
		}
		return err
	}
	return nil
}

func urlUser(s string) string {
	r := strings.NewReplacer(":", "%3A", "/", "%2F", "@", "%40", "?", "%3F", "#", "%23", "%", "%25")
	return r.Replace(s)
}

func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func pgQuoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

func mysqlQuoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}

func mysqlQuoteLiteral(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	r = strings.ReplaceAll(r, `'`, `\'`)
	return `'` + r + `'`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
