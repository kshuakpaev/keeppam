package assets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

const (
	SyncOrderDirectoryFirst = "directory_first"
	SyncOrderDirectoryLast  = "directory_last"
)

type PasswordSet struct {
	ID          uuid.UUID            `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	SyncOrder   string               `json:"sync_order"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	CreatedBy   *uuid.UUID           `json:"created_by,omitempty"`
	Members     []PasswordSetMember  `json:"members,omitempty"`
}

type PasswordSetMember struct {
	AccountID   uuid.UUID `json:"account_id"`
	AssetID     uuid.UUID `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	Protocol    string    `json:"protocol"`
	Username    string    `json:"username"`
	AuthMethod  string    `json:"auth_method"`
	Directory   bool      `json:"directory"`
	SortOrder   int       `json:"sort_order"`
}

type CreatePasswordSetInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	SyncOrder   string   `json:"sync_order"`
	AccountIDs  []string `json:"account_ids"`
}

type UpdatePasswordSetInput struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	SyncOrder   *string  `json:"sync_order"`
	AccountIDs  []string `json:"account_ids"` // replace members when non-nil (use empty slice to clear)
}

type PasswordSetRotateResult struct {
	SetID   uuid.UUID                    `json:"set_id"`
	Results []PasswordSetMemberRotateRes `json:"results"`
}

type PasswordSetMemberRotateRes struct {
	AccountID uuid.UUID `json:"account_id"`
	AssetID   uuid.UUID `json:"asset_id"`
	Username  string    `json:"username"`
	OK        bool      `json:"ok"`
	Remote    bool      `json:"remote_applied"`
	Error     string    `json:"error,omitempty"`
}

func normalizeSyncOrder(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return SyncOrderDirectoryLast, nil
	}
	switch v {
	case SyncOrderDirectoryFirst, SyncOrderDirectoryLast:
		return v, nil
	default:
		return "", fmt.Errorf("sync_order must be directory_first or directory_last")
	}
}

func (s *Service) ListPasswordSets(ctx context.Context) ([]PasswordSet, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, sync_order, created_at, updated_at, created_by
		FROM password_sets ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PasswordSet
	for rows.Next() {
		var p PasswordSet
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SyncOrder, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) GetPasswordSet(ctx context.Context, id uuid.UUID) (PasswordSet, error) {
	var p PasswordSet
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, sync_order, created_at, updated_at, created_by
		FROM password_sets WHERE id=$1`, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.SyncOrder, &p.CreatedAt, &p.UpdatedAt, &p.CreatedBy)
	if err != nil {
		return PasswordSet{}, err
	}
	members, err := s.listPasswordSetMembers(ctx, id)
	if err != nil {
		return PasswordSet{}, err
	}
	p.Members = members
	return p, nil
}

func (s *Service) CreatePasswordSet(ctx context.Context, actorID uuid.UUID, in CreatePasswordSetInput, ip, ua string) (PasswordSet, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return PasswordSet{}, fmt.Errorf("name required")
	}
	order, err := normalizeSyncOrder(in.SyncOrder)
	if err != nil {
		return PasswordSet{}, err
	}
	ids, err := parseAccountIDs(in.AccountIDs)
	if err != nil {
		return PasswordSet{}, err
	}
	now := time.Now().UTC()
	id := store.NewID()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return PasswordSet{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO password_sets (id, name, description, sync_order, created_at, updated_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, name, strings.TrimSpace(in.Description), order, now, now, actorID)
	if err != nil {
		return PasswordSet{}, err
	}
	if err := replacePasswordSetMembersTx(ctx, tx, id, ids); err != nil {
		return PasswordSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PasswordSet{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "password_set.created", "password_set", id.String(), ip, ua, map[string]any{
		"name": name, "members": len(ids), "sync_order": order,
	})
	return s.GetPasswordSet(ctx, id)
}

func (s *Service) UpdatePasswordSet(ctx context.Context, actorID, id uuid.UUID, in UpdatePasswordSetInput, ip, ua string) (PasswordSet, error) {
	cur, err := s.GetPasswordSet(ctx, id)
	if err != nil {
		return PasswordSet{}, err
	}
	name := cur.Name
	desc := cur.Description
	order := cur.SyncOrder
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if name == "" {
			return PasswordSet{}, fmt.Errorf("name required")
		}
	}
	if in.Description != nil {
		desc = strings.TrimSpace(*in.Description)
	}
	if in.SyncOrder != nil {
		order, err = normalizeSyncOrder(*in.SyncOrder)
		if err != nil {
			return PasswordSet{}, err
		}
	}
	now := time.Now().UTC()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return PasswordSet{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		UPDATE password_sets SET name=$2, description=$3, sync_order=$4, updated_at=$5 WHERE id=$1`,
		id, name, desc, order, now)
	if err != nil {
		return PasswordSet{}, err
	}
	if in.AccountIDs != nil {
		ids, err := parseAccountIDs(in.AccountIDs)
		if err != nil {
			return PasswordSet{}, err
		}
		if err := replacePasswordSetMembersTx(ctx, tx, id, ids); err != nil {
			return PasswordSet{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return PasswordSet{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "password_set.updated", "password_set", id.String(), ip, ua, map[string]any{
		"name": name, "sync_order": order,
	})
	return s.GetPasswordSet(ctx, id)
}

func (s *Service) DeletePasswordSet(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	cur, err := s.GetPasswordSet(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, `DELETE FROM password_sets WHERE id=$1`, id)
	if err != nil {
		return err
	}
	return s.aud.Record(ctx, &actorID, "password_set.deleted", "password_set", id.String(), ip, ua, map[string]any{
		"name": cur.Name,
	})
}

func (s *Service) RotatePasswordSet(ctx context.Context, actorID, setID uuid.UUID, in RotateInput, ip, ua string) (PasswordSetRotateResult, error) {
	set, err := s.GetPasswordSet(ctx, setID)
	if err != nil {
		return PasswordSetRotateResult{}, err
	}
	members, err := s.orderedPasswordSetMembers(ctx, set)
	if err != nil {
		return PasswordSetRotateResult{}, err
	}
	if len(members) == 0 {
		return PasswordSetRotateResult{}, fmt.Errorf("password set has no members")
	}
	newSecret := strings.TrimSpace(in.NewSecret)
	if newSecret == "" {
		newSecret, err = generatePassword(24)
		if err != nil {
			return PasswordSetRotateResult{}, err
		}
	} else if len(newSecret) < 8 {
		return PasswordSetRotateResult{}, fmt.Errorf("secret too short (min 8)")
	}
	applyRemote := true
	if in.ApplyRemote != nil {
		applyRemote = *in.ApplyRemote
	}
	out := PasswordSetRotateResult{SetID: setID}
	for _, m := range members {
		if m.AuthMethod != "password" {
			out.Results = append(out.Results, PasswordSetMemberRotateRes{
				AccountID: m.AccountID, AssetID: m.AssetID, Username: m.Username,
				Error: "auth_method is not password",
			})
			continue
		}
		ar := applyRemote
		res, err := s.RotateSecret(ctx, actorID, m.AssetID, m.AccountID, RotateInput{
			NewSecret: newSecret, ApplyRemote: &ar, SkipPeerSync: true,
		}, ip, ua)
		item := PasswordSetMemberRotateRes{
			AccountID: m.AccountID, AssetID: m.AssetID, Username: m.Username,
			OK: err == nil, Remote: res.Remote,
		}
		if err != nil {
			item.Error = truncate(err.Error(), 300)
		}
		out.Results = append(out.Results, item)
	}
	okCount := 0
	for _, r := range out.Results {
		if r.OK {
			okCount++
		}
	}
	_ = s.aud.Record(ctx, &actorID, "password_set.rotated", "password_set", setID.String(), ip, ua, map[string]any{
		"name": set.Name, "ok": okCount, "total": len(out.Results), "apply_remote": applyRemote,
	})
	return out, nil
}

func (s *Service) listPasswordSetMembers(ctx context.Context, setID uuid.UUID) ([]PasswordSetMember, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT m.account_id, a.asset_id, ast.name, ast.protocol, a.username, a.auth_method, m.sort_order,
			COALESCE(ast.ad_privileged_group_dn,''), COALESCE(a.ad_user_dn,'')
		FROM password_set_members m
		JOIN asset_accounts a ON a.id = m.account_id
		JOIN assets ast ON ast.id = a.asset_id
		WHERE m.set_id=$1
		ORDER BY m.sort_order, ast.name, a.username`, setID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PasswordSetMember
	for rows.Next() {
		var m PasswordSetMember
		var groupDN, userDN string
		if err := rows.Scan(&m.AccountID, &m.AssetID, &m.AssetName, &m.Protocol, &m.Username, &m.AuthMethod, &m.SortOrder, &groupDN, &userDN); err != nil {
			return nil, err
		}
		m.Directory = strings.TrimSpace(groupDN) != "" || strings.TrimSpace(userDN) != ""
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) orderedPasswordSetMembers(ctx context.Context, set PasswordSet) ([]PasswordSetMember, error) {
	members := set.Members
	if members == nil {
		var err error
		members, err = s.listPasswordSetMembers(ctx, set.ID)
		if err != nil {
			return nil, err
		}
	}
	var dir, host []PasswordSetMember
	for _, m := range members {
		if m.Directory {
			dir = append(dir, m)
		} else {
			host = append(host, m)
		}
	}
	if set.SyncOrder == SyncOrderDirectoryFirst {
		return append(dir, host...), nil
	}
	return append(host, dir...), nil
}

func (s *Service) findPasswordSetIDByAccount(ctx context.Context, accountID uuid.UUID) (uuid.UUID, bool, error) {
	var id uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `
		SELECT set_id FROM password_set_members WHERE account_id=$1`, accountID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, err
	}
	return id, true, nil
}

// syncPeersAfterRotate pushes the same password to other members of the account's password set.
func (s *Service) syncPeersAfterRotate(ctx context.Context, actorID, accountID uuid.UUID, newSecret string, applyRemote bool, ip, ua string) {
	setID, ok, err := s.findPasswordSetIDByAccount(ctx, accountID)
	if err != nil || !ok {
		return
	}
	set, err := s.GetPasswordSet(ctx, setID)
	if err != nil {
		return
	}
	members, err := s.orderedPasswordSetMembers(ctx, set)
	if err != nil {
		return
	}
	for _, m := range members {
		if m.AccountID == accountID || m.AuthMethod != "password" {
			continue
		}
		ar := applyRemote
		_, _ = s.RotateSecret(ctx, actorID, m.AssetID, m.AccountID, RotateInput{
			NewSecret: newSecret, ApplyRemote: &ar, SkipPeerSync: true,
		}, ip, ua)
	}
}

func parseAccountIDs(raw []string) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]struct{}{}
	var out []uuid.UUID
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("invalid account_id %q", s)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func replacePasswordSetMembersTx(ctx context.Context, tx pgx.Tx, setID uuid.UUID, accountIDs []uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM password_set_members WHERE set_id=$1`, setID); err != nil {
		return err
	}
	for i, accID := range accountIDs {
		var n int
		err := tx.QueryRow(ctx, `SELECT 1 FROM asset_accounts WHERE id=$1`, accID).Scan(&n)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("account %s not found", accID)
			}
			return err
		}
		var other uuid.UUID
		err = tx.QueryRow(ctx, `
			SELECT set_id FROM password_set_members WHERE account_id=$1 AND set_id<>$2`, accID, setID).Scan(&other)
		if err == nil {
			return fmt.Errorf("account %s already in another password set", accID)
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO password_set_members (set_id, account_id, sort_order) VALUES ($1,$2,$3)`,
			setID, accID, i); err != nil {
			return err
		}
	}
	return nil
}
