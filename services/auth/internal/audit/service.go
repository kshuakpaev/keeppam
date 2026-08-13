package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Record(ctx context.Context, actorID *uuid.UUID, action, resourceType, resourceID, ip, ua string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	prev, err := s.db.LatestAuditHash(ctx)
	if err != nil {
		return err
	}
	id := store.NewID()
	ts := time.Now().UTC()
	h := computeHash(prev, id, ts, actorID, action, resourceType, resourceID, payload)
	err = s.db.InsertAudit(ctx, store.AuditEvent{
		ID: id, TS: ts, ActorID: actorID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID,
		IP: ip, UserAgent: ua, Payload: payload, PrevHash: prev, Hash: h,
	})
	if err == nil {
		obs.Default.IncAudit()
	}
	return err
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

func computeHash(prev string, id uuid.UUID, ts time.Time, actorID *uuid.UUID, action, rt, rid string, payload map[string]any) string {
	actor := ""
	if actorID != nil {
		actor = actorID.String()
	}
	pb, _ := json.Marshal(payload)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", prev, id, ts.UTC().Format(time.RFC3339Nano), actor, action, rt, rid, string(pb))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
