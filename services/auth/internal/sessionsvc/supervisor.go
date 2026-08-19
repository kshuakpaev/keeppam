package sessionsvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrWaitingSupervisor = errors.New("waiting for supervisor")

const supervisorWaitTimeout = 15 * time.Minute

func (s Session) IsWaitingSupervisor() bool {
	return s.RequireSupervisor && s.SupervisorApprovedAt == nil && s.Status == "pending"
}

func (s *Service) ApproveSupervisor(ctx context.Context, actorID, sessionID uuid.UUID, ip, ua string) (Session, error) {
	row, err := s.Get(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	if row.Status != "pending" {
		return Session{}, fmt.Errorf("session is not pending")
	}
	if !row.RequireSupervisor {
		return Session{}, fmt.Errorf("session does not require a supervisor")
	}
	if row.SupervisorApprovedAt != nil {
		return Session{}, fmt.Errorf("already authorized")
	}
	if row.UserID == actorID {
		return Session{}, fmt.Errorf("dual control: cannot supervise your own session")
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions
		SET supervisor_id=$2, supervisor_approved_at=NOW()
		WHERE id=$1 AND status='pending' AND require_supervisor AND supervisor_approved_at IS NULL`,
		sessionID, actorID)
	if err != nil {
		return Session{}, err
	}
	if tag.RowsAffected() == 0 {
		return Session{}, fmt.Errorf("session is not waiting for supervisor")
	}
	_ = s.aud.Record(ctx, &actorID, "session.supervisor.approved", "session", sessionID.String(), ip, ua, map[string]any{
		"user_id": row.UserID.String(), "asset_id": row.AssetID.String(),
	})
	_ = s.AddEvent(ctx, sessionID, "supervisor_approved", map[string]any{"actor_id": actorID.String()})
	return s.Get(ctx, sessionID)
}

func (s *Service) DenySupervisor(ctx context.Context, actorID, sessionID uuid.UUID, ip, ua string) (Session, error) {
	row, err := s.Get(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	if row.Status != "pending" {
		return Session{}, fmt.Errorf("session is not pending")
	}
	if !row.RequireSupervisor || row.SupervisorApprovedAt != nil {
		return Session{}, fmt.Errorf("session is not waiting for supervisor")
	}
	if row.UserID == actorID {
		return Session{}, fmt.Errorf("dual control: cannot supervise your own session")
	}
	if err := s.MarkEnded(ctx, sessionID, "denied by supervisor"); err != nil {
		return Session{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "session.supervisor.denied", "session", sessionID.String(), ip, ua, map[string]any{
		"user_id": row.UserID.String(), "asset_id": row.AssetID.String(),
	})
	return s.Get(ctx, sessionID)
}

func (s *Service) CountWaitingSupervisor(ctx context.Context) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE status='pending' AND require_supervisor AND supervisor_approved_at IS NULL`).Scan(&n)
	return n, err
}

func (s *Service) ExpireWaitingSupervisor(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		olderThan = supervisorWaitTimeout
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE sessions
		SET status='failed', ended_at=NOW(), error_message='supervisor timeout'
		WHERE status='pending' AND require_supervisor AND supervisor_approved_at IS NULL
		  AND created_at < $1
		RETURNING id`, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return n, err
		}
		_ = s.AddEvent(ctx, id, "failed", map[string]any{"error": "supervisor timeout"})
		n++
	}
	return n, rows.Err()
}

// WaitSupervisor blocks until a supervisor authorizes, the session ends, or timeout.
func (s *Service) WaitSupervisor(ctx context.Context, id uuid.UUID, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = supervisorWaitTimeout
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		row, err := s.Get(ctx, id)
		if err != nil {
			return err
		}
		if !row.IsWaitingSupervisor() {
			if row.Status == "ended" || row.Status == "failed" {
				msg := row.ErrorMessage
				if msg == "" {
					msg = "session closed"
				}
				return fmt.Errorf("%s", msg)
			}
			return nil
		}
		if time.Now().After(deadline) {
			_ = s.MarkEnded(ctx, id, "supervisor timeout")
			return fmt.Errorf("supervisor timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func IsWaitingSupervisor(err error) bool {
	return errors.Is(err, ErrWaitingSupervisor)
}
