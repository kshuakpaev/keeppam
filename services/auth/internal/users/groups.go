package users

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type Group struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	MemberCount int          `json:"member_count"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Members     []store.User `json:"members,omitempty"`
}

type GroupInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	MemberIDs   []string `json:"member_ids"`
}

func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
		       (SELECT COUNT(*) FROM user_group_members m WHERE m.group_id=g.id)
		FROM groups g ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if out == nil {
		out = []Group{}
	}
	return out, rows.Err()
}

func (s *Service) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	var g Group
	err := s.db.Pool.QueryRow(ctx, `
		SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
		       (SELECT COUNT(*) FROM user_group_members m WHERE m.group_id=g.id)
		FROM groups g WHERE g.id=$1`, id).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount)
	if err != nil {
		return Group{}, err
	}
	members, err := s.groupMembers(ctx, id)
	if err != nil {
		return Group{}, err
	}
	g.Members = members
	return g, nil
}

func (s *Service) groupMembers(ctx context.Context, groupID uuid.UUID) ([]store.User, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.display_name, u.status
		FROM user_group_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.group_id=$1 ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.User
	for rows.Next() {
		var u store.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.Status); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if out == nil {
		out = []store.User{}
	}
	return out, rows.Err()
}

func (s *Service) CreateGroup(ctx context.Context, actorID uuid.UUID, in GroupInput, ip, ua string) (Group, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		return Group{}, fmt.Errorf("name required")
	}
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO groups (id, name, description, created_at, updated_at, created_by)
		VALUES ($1,$2,$3,NOW(),NOW(),$4)`, id, name, strings.TrimSpace(in.Description), actorID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return Group{}, fmt.Errorf("group already exists")
		}
		return Group{}, err
	}
	if err := s.replaceMembers(ctx, id, in.MemberIDs); err != nil {
		return Group{}, err
	}
	_ = s.audit.Record(ctx, &actorID, "group.created", "group", id.String(), ip, ua, map[string]any{"name": name})
	return s.GetGroup(ctx, id)
}

func (s *Service) UpdateGroup(ctx context.Context, actorID, id uuid.UUID, in GroupInput, ip, ua string) (Group, error) {
	cur, err := s.GetGroup(ctx, id)
	if err != nil {
		return Group{}, err
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		name = cur.Name
	}
	desc := in.Description
	_, err = s.db.Pool.Exec(ctx, `UPDATE groups SET name=$2, description=$3, updated_at=NOW() WHERE id=$1`, id, name, desc)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return Group{}, fmt.Errorf("group already exists")
		}
		return Group{}, err
	}
	if in.MemberIDs != nil {
		if err := s.replaceMembers(ctx, id, in.MemberIDs); err != nil {
			return Group{}, err
		}
	}
	_ = s.audit.Record(ctx, &actorID, "group.updated", "group", id.String(), ip, ua, map[string]any{"name": name})
	return s.GetGroup(ctx, id)
}

func (s *Service) DeleteGroup(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.audit.Record(ctx, &actorID, "group.deleted", "group", id.String(), ip, ua, nil)
}

func (s *Service) replaceMembers(ctx context.Context, groupID uuid.UUID, ids []string) error {
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM user_group_members WHERE group_id=$1`, groupID); err != nil {
		return err
	}
	seen := map[uuid.UUID]struct{}{}
	for _, raw := range ids {
		uid, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid member id")
		}
		if _, ok := seen[uid]; ok {
			continue
		}
		seen[uid] = struct{}{}
		if _, err := s.db.Pool.Exec(ctx, `
			INSERT INTO user_group_members (user_id, group_id) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, uid, groupID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) SetUserGroups(ctx context.Context, actorID, userID uuid.UUID, groupIDs []string, ip, ua string) error {
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM user_group_members WHERE user_id=$1`, userID); err != nil {
		return err
	}
	seen := map[uuid.UUID]struct{}{}
	for _, raw := range groupIDs {
		gid, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid group id")
		}
		if _, ok := seen[gid]; ok {
			continue
		}
		seen[gid] = struct{}{}
		if _, err := s.db.Pool.Exec(ctx, `
			INSERT INTO user_group_members (user_id, group_id) VALUES ($1,$2)
			ON CONFLICT DO NOTHING`, userID, gid); err != nil {
			return err
		}
	}
	return s.audit.Record(ctx, &actorID, "group.membership", "user", userID.String(), ip, ua, map[string]any{"group_ids": groupIDs})
}
