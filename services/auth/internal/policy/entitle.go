package policy

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type assetIDMeta struct {
	ID   uuid.UUID
	Meta AssetMeta
}

// EntitledAssetIDs returns assets the user may connect to: standing/JIT ACL
// (user, role, or group) that has not expired, plus assets they own.
// Time-of-day / CIDR / ticket are checked at Evaluate (connect), not here.
func (s *Service) EntitledAssetIDs(ctx context.Context, userID uuid.UUID, roleNames []string, now time.Time) ([]uuid.UUID, error) {
	if now.IsZero() {
		now = time.Now()
	}
	set := map[uuid.UUID]struct{}{}

	owned, err := s.db.Pool.Query(ctx, `SELECT id FROM assets WHERE owner_user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer owned.Close()
	for owned.Next() {
		var id uuid.UUID
		if err := owned.Scan(&id); err != nil {
			return nil, err
		}
		set[id] = struct{}{}
	}
	if err := owned.Err(); err != nil {
		return nil, err
	}

	groups, err := s.userGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	gids := make([]uuid.UUID, 0, len(groups))
	for id := range groups {
		gids = append(gids, id)
	}
	roles := append([]string{}, roleNames...)
	if roles == nil {
		roles = []string{}
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT b.asset_id,
			COALESCE(b.asset_match_tags,'{}'), COALESCE(b.asset_match_mode,'all'),
			COALESCE(b.asset_match_name,''), COALESCE(b.asset_match_hostname,''),
			COALESCE(b.asset_match_types,'{}'), COALESCE(b.asset_match_cidrs,'{}')
		FROM asset_access_bindings b
		LEFT JOIN roles r ON r.id = b.role_id
		WHERE (b.expires_at IS NULL OR b.expires_at > $1)
		  AND (
			b.user_id = $2
			OR (r.name IS NOT NULL AND r.name = ANY($3))
			OR (b.group_id IS NOT NULL AND b.group_id = ANY($4))
		  )`, now.UTC(), userID, roles, gids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dyn []AssetSelector
	for rows.Next() {
		var assetID *uuid.UUID
		var matchTags, matchTypes, matchCIDRs []string
		var matchMode, matchName, matchHost string
		if err := rows.Scan(&assetID, &matchTags, &matchMode, &matchName, &matchHost, &matchTypes, &matchCIDRs); err != nil {
			return nil, err
		}
		if assetID != nil {
			set[*assetID] = struct{}{}
			continue
		}
		sel := AssetSelector{Tags: matchTags, Mode: matchMode, Name: matchName, Hostname: matchHost, Types: matchTypes, CIDRs: matchCIDRs}
		if !sel.Empty() {
			dyn = append(dyn, sel)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(dyn) > 0 {
		metas, err := s.listAssetMetas(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range metas {
			for _, sel := range dyn {
				if sel.MatchAsset(row.Meta) {
					set[row.ID] = struct{}{}
					break
				}
			}
		}
	}

	out := make([]uuid.UUID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out, nil
}

func (s *Service) listAssetMetas(ctx context.Context) ([]assetIDMeta, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT a.id, a.name, COALESCE(a.hostname,''), COALESCE(a.address,''), COALESCE(a.asset_type,''), a.owner_user_id,
			COALESCE(ARRAY(SELECT t.tag FROM asset_tags t WHERE t.asset_id = a.id), '{}')
		FROM assets a`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []assetIDMeta
	for rows.Next() {
		var row assetIDMeta
		if err := rows.Scan(&row.ID, &row.Meta.Name, &row.Meta.Hostname, &row.Meta.Address, &row.Meta.Type, &row.Meta.OwnerUserID, &row.Meta.Tags); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
