package sessionsvc

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
)

const uebaLockTTL = 24 * time.Hour

func (s *Service) SetLiveHub(h *LiveHub) {
	s.live = h
}

func (s *Service) ApplyRiskBreach(ctx context.Context, userID, sessionID, assetID uuid.UUID, action string, score int, ip string) {
	if s == nil || userID == uuid.Nil || !policy.IsHardRiskAction(action) {
		return
	}
	if action == "lock_account" {
		s.lockUser(ctx, userID, ip, score)
		s.endUserSessions(ctx, userID, "ueba risk lock_account")
		return
	}
	if sessionID != uuid.Nil {
		s.endOne(ctx, sessionID, "ueba risk terminate")
		return
	}
	if assetID != uuid.Nil {
		var id uuid.UUID
		err := s.db.Pool.QueryRow(ctx, `
			SELECT id FROM sessions
			WHERE user_id=$1 AND asset_id=$2 AND status IN ('pending','active')
			ORDER BY created_at DESC LIMIT 1`, userID, assetID).Scan(&id)
		if err == nil && id != uuid.Nil {
			s.endOne(ctx, id, "ueba risk terminate")
		}
	}
}

func (s *Service) lockUser(ctx context.Context, userID uuid.UUID, ip string, score int) {
	until := time.Now().UTC().Add(uebaLockTTL)
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET status='locked', locked_until=$2, updated_at=NOW()
		WHERE id=$1 AND status <> 'disabled'`, userID, until)
	if err != nil {
		return
	}
	_ = s.aud.Record(ctx, &userID, "user.locked", "user", userID.String(), ip, "", map[string]any{
		"reason": "ueba_risk", "score": score, "until": until.Format(time.RFC3339),
	})
}

func (s *Service) endUserSessions(ctx context.Context, userID uuid.UUID, reason string) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id FROM sessions WHERE user_id=$1 AND status IN ('pending','active')`, userID)
	if err != nil {
		return
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		s.endOne(ctx, id, reason)
	}
}

func (s *Service) endOne(ctx context.Context, id uuid.UUID, reason string) {
	if s.live != nil {
		s.live.Kill(ctx, id)
	}
	_ = s.MarkEnded(ctx, id, reason)
	_ = s.aud.Record(ctx, nil, "session.ended", "session", id.String(), "", "", map[string]any{
		"via": "ueba_risk", "forced": true, "reason": reason,
	})
}

func (s *Service) maybeEnforceAfterRisk(ctx context.Context, row Session, score int) {
	if row.PolicySnapshot == nil || row.PolicySnapshot.MaxRisk <= 0 {
		return
	}
	if score <= row.PolicySnapshot.MaxRisk {
		return
	}
	action := row.PolicySnapshot.RiskAction
	if action == "" {
		action = "deny"
	}
	s.ApplyRiskBreach(ctx, row.UserID, row.ID, row.AssetID, action, score, row.ClientIP)
}
