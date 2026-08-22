package uebaml

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/keeppam/auth/internal/ueba"
)

type PeerGroup struct {
	ID      uuid.UUID
	Name    string
	Members int
}

func loadPeerGroup(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) (PeerGroup, error) {
	var g PeerGroup
	err := pool.QueryRow(ctx, `
		SELECT g.id, g.name,
			(SELECT COUNT(*) FROM user_group_members m2 WHERE m2.group_id = g.id)
		FROM user_groups g
		JOIN user_group_members m ON m.group_id = g.id
		WHERE m.user_id = $1
		ORDER BY (SELECT COUNT(*) FROM user_group_members m3 WHERE m3.group_id = g.id) DESC, g.name
		LIMIT 1`, userID).Scan(&g.ID, &g.Name, &g.Members)
	return g, err
}

// PeerAssetAccessRatio returns fraction of peer-group members who accessed asset since.
func PeerAssetAccessRatio(ctx context.Context, pool *pgxpool.Pool, groupID, assetID uuid.UUID, since time.Time) (ratio float64, members int, err error) {
	err = pool.QueryRow(ctx, `
		WITH peers AS (
			SELECT user_id FROM user_group_members WHERE group_id = $1
		)
		SELECT
			COUNT(DISTINCT p.user_id),
			COALESCE(COUNT(DISTINCT p.user_id) FILTER (
				WHERE EXISTS (
					SELECT 1 FROM sessions s
					WHERE s.user_id = p.user_id AND s.asset_id = $2
					  AND s.created_at >= $3 AND s.`+ueba.SessionSQL+`
				)
			), 0)
		FROM peers p`, groupID, assetID, since.UTC()).Scan(&members, &ratio)
	if err != nil || members == 0 {
		return 0, members, err
	}
	withAccess := ratio
	ratio = float64(withAccess) / float64(members)
	return ratio, members, nil
}

func peerOutlier(ratio float64, members int) bool {
	return members >= MinPeerMembers && ratio < PeerRareRatio
}
