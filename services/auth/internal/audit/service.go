package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db  *store.DB
	mac *crypto.Envelope
}

func New(db *store.DB) *Service {
	return &Service{db: db}
}

func (s *Service) SetMAC(env *crypto.Envelope) {
	s.mac = env
}

func (s *Service) Record(ctx context.Context, actorID *uuid.UUID, action, resourceType, resourceID, ip, ua string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return err
	}
	prev := ""
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY ts DESC, id DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	id := store.NewID()
	ts := time.Now().UTC().Truncate(time.Microsecond)
	h := Hash(prev, id, ts, actorID, action, resourceType, resourceID, payload)
	if err := s.db.InsertAuditTx(ctx, tx, store.AuditEvent{
		ID: id, TS: ts, ActorID: actorID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID,
		IP: ip, UserAgent: ua, Payload: payload, PrevHash: prev, Hash: h,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	obs.Default.IncAudit()
	return nil
}

func (s *Service) List(ctx context.Context, f store.AuditFilter) ([]store.AuditEvent, int, error) {
	total, err := s.db.CountAudit(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	events, err := s.db.ListAudit(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}
