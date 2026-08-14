package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/store"
)

type BreakGlassInput struct {
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

type BreakGlassEvent struct {
	ID              uuid.UUID  `json:"id"`
	AssetID         uuid.UUID  `json:"asset_id"`
	UserID          uuid.UUID  `json:"user_id"`
	Reason          string     `json:"reason"`
	DurationMinutes int        `json:"duration_minutes"`
	BindingID       *uuid.UUID `json:"binding_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ClosedAt        *time.Time `json:"closed_at,omitempty"`
	AssetName       string     `json:"asset_name,omitempty"`
	Username        string     `json:"username,omitempty"`
	Active          bool       `json:"active"`
}

func (s *Service) OpenBreakGlass(ctx context.Context, actorID, assetID uuid.UUID, in BreakGlassInput, ip, ua string) (BreakGlassEvent, error) {
	reason := strings.TrimSpace(in.Reason)
	if len(reason) < 20 {
		return BreakGlassEvent{}, fmt.Errorf("reason required (min 20 characters) — break-glass is audited")
	}
	if len(reason) > 2000 {
		return BreakGlassEvent{}, fmt.Errorf("reason too long")
	}
	dur := in.DurationMinutes
	if dur <= 0 {
		dur = 30
	}
	if dur > 60 {
		return BreakGlassEvent{}, fmt.Errorf("break-glass TTL max 60 minutes")
	}
	var exists bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1 AND status='active')`, assetID).Scan(&exists); err != nil {
		return BreakGlassEvent{}, err
	}
	if !exists {
		return BreakGlassEvent{}, fmt.Errorf("asset not found or disabled")
	}

	uid := actorID
	b, err := s.Create(ctx, actorID, assetID, CreateBindingInput{
		UserID:          &uid,
		DurationMinutes: &dur,
		RequireReason:   true,
	}, ip, ua)
	if err != nil {
		return BreakGlassEvent{}, err
	}
	id := store.NewID()
	now := time.Now().UTC()
	exp := now.Add(time.Duration(dur) * time.Minute)
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO break_glass_events (id, asset_id, user_id, reason, duration_minutes, binding_id, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, assetID, actorID, reason, dur, b.ID, now, exp)
	if err != nil {
		return BreakGlassEvent{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "access.breakglass.opened", "asset", assetID.String(), ip, ua, map[string]any{
		"severity":         "critical",
		"reason":           reason,
		"duration_minutes": dur,
		"binding_id":       b.ID.String(),
		"event_id":         id.String(),
		"expires_at":       exp.Format(time.RFC3339),
	})
	return s.GetBreakGlass(ctx, id)
}

func (s *Service) GetBreakGlass(ctx context.Context, id uuid.UUID) (BreakGlassEvent, error) {
	row := s.db.Pool.QueryRow(ctx, breakGlassSelect+` WHERE e.id=$1`, id)
	return scanBreakGlass(row)
}

func (s *Service) ListBreakGlass(ctx context.Context, activeOnly bool) ([]BreakGlassEvent, error) {
	q := breakGlassSelect
	if activeOnly {
		q += ` WHERE e.closed_at IS NULL AND e.expires_at > NOW()`
	}
	q += ` ORDER BY e.created_at DESC LIMIT 100`
	rows, err := s.db.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BreakGlassEvent
	for rows.Next() {
		ev, err := scanBreakGlass(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if out == nil {
		out = []BreakGlassEvent{}
	}
	return out, rows.Err()
}

func (s *Service) CloseExpiredBreakGlass(ctx context.Context) (int, error) {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE break_glass_events SET closed_at=NOW()
		WHERE closed_at IS NULL AND expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

const breakGlassSelect = `
	SELECT e.id, e.asset_id, e.user_id, e.reason, e.duration_minutes, e.binding_id,
		e.created_at, e.expires_at, e.closed_at, a.name, u.username
	FROM break_glass_events e
	JOIN assets a ON a.id=e.asset_id
	JOIN users u ON u.id=e.user_id`

type bgScanner interface {
	Scan(dest ...any) error
}

func scanBreakGlass(row bgScanner) (BreakGlassEvent, error) {
	var e BreakGlassEvent
	err := row.Scan(&e.ID, &e.AssetID, &e.UserID, &e.Reason, &e.DurationMinutes, &e.BindingID,
		&e.CreatedAt, &e.ExpiresAt, &e.ClosedAt, &e.AssetName, &e.Username)
	if err != nil {
		return e, err
	}
	e.Active = e.ClosedAt == nil && time.Now().UTC().Before(e.ExpiresAt)
	return e, nil
}

func (s *Service) HasActiveBreakGlass(ctx context.Context, userID, assetID uuid.UUID) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM break_glass_events
		WHERE user_id=$1 AND asset_id=$2 AND closed_at IS NULL AND expires_at > NOW()`,
		userID, assetID).Scan(&n)
	return n > 0, err
}
