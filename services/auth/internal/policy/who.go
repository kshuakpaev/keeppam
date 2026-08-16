package policy

import (
	"context"

	"github.com/google/uuid"
)

func matchWHO(userID uuid.UUID, uid, rid, gid *uuid.UUID, roleName *string, roleSet map[string]struct{}, groupSet map[uuid.UUID]struct{}) bool {
	if uid != nil && *uid == userID {
		return true
	}
	if rid != nil && roleName != nil {
		if _, ok := roleSet[*roleName]; ok {
			return true
		}
	}
	if gid != nil {
		if _, ok := groupSet[*gid]; ok {
			return true
		}
	}
	return false
}

func (s *Service) userGroupIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	out := map[uuid.UUID]struct{}{}
	if userID == uuid.Nil {
		return out, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		WITH RECURSIVE tree AS (
			SELECT g.id, g.parent_id, 1 AS depth
			FROM groups g
			JOIN user_group_members m ON m.group_id = g.id
			WHERE m.user_id=$1
			UNION ALL
			SELECT p.id, p.parent_id, t.depth+1
			FROM groups p
			JOIN tree t ON t.parent_id = p.id
			WHERE t.depth < 8
		)
		SELECT DISTINCT id FROM tree`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

func (s *Service) userGroupNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `
		WITH RECURSIVE tree AS (
			SELECT g.id, g.parent_id, g.name, 1 AS depth
			FROM groups g
			JOIN user_group_members m ON m.group_id = g.id
			WHERE m.user_id=$1
			UNION ALL
			SELECT p.id, p.parent_id, p.name, t.depth+1
			FROM groups p
			JOIN tree t ON t.parent_id = p.id
			WHERE t.depth < 8
		)
		SELECT DISTINCT name FROM tree ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if out == nil {
		out = []string{}
	}
	return out, rows.Err()
}

// EffectiveGroupNames is direct membership plus ancestor groups (child implies parent).
func (s *Service) EffectiveGroupNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.userGroupNames(ctx, userID)
}
