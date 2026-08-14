package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/store"
)

func Hash(prev string, id uuid.UUID, ts time.Time, actorID *uuid.UUID, action, rt, rid string, payload map[string]any) string {
	if payload == nil {
		payload = map[string]any{}
	}
	actor := ""
	if actorID != nil {
		actor = actorID.String()
	}
	pb, _ := json.Marshal(payload)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		prev, id.String(), ts.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		actor, action, rt, rid, string(pb))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func HashEvent(e store.AuditEvent) string {
	return Hash(e.PrevHash, e.ID, e.TS, e.ActorID, e.Action, e.ResourceType, e.ResourceID, e.Payload)
}
