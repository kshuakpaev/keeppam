package siem

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/keeppam/auth/internal/store"
)

const ecsVersion = "8.11.0"

// EventECS maps an audit row to Elastic Common Schema (OpenSearch-compatible).
func EventECS(e store.AuditEvent) map[string]any {
	ev := map[string]any{
		"id":       e.ID.String(),
		"action":   e.Action,
		"dataset":  "keeppam.audit",
		"kind":     "event",
		"module":   "keeppam",
		"provider": "keeppam",
		"category": ecsCategory(e.Action),
	}
	if o := ecsOutcome(e.Action); o != "" {
		ev["outcome"] = o
	}
	doc := map[string]any{
		"@timestamp": e.TS.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"event":      ev,
		"tags":       []string{"keeppam", "audit"},
		"message":    strings.TrimSpace(e.Action + " " + strings.TrimSpace(e.ResourceType+" "+e.ResourceID)),
		"keeppam": map[string]any{
			"resource": map[string]any{
				"type": e.ResourceType,
				"id":   e.ResourceID,
			},
			"hash":      e.Hash,
			"prev_hash": e.PrevHash,
			"payload":   e.Payload,
		},
	}
	if e.ActorID != nil {
		doc["user"] = map[string]any{"id": e.ActorID.String()}
	}
	if e.IP != "" {
		doc["source"] = map[string]any{"ip": e.IP}
	}
	if e.UserAgent != "" {
		doc["user_agent"] = map[string]any{"original": e.UserAgent}
	}
	if e.Payload == nil {
		kp := doc["keeppam"].(map[string]any)
		kp["payload"] = map[string]any{}
	}
	return doc
}

func ecsCategory(action string) []string {
	switch {
	case strings.HasPrefix(action, "user.login"), strings.HasPrefix(action, "user.mfa"), strings.HasPrefix(action, "user.webauthn"):
		return []string{"authentication"}
	case strings.HasPrefix(action, "session."):
		return []string{"session"}
	default:
		return []string{"iam"}
	}
}

func ecsOutcome(action string) string {
	a := strings.ToLower(action)
	switch {
	case strings.Contains(a, "denied"), strings.Contains(a, "failed"), strings.Contains(a, "timeout"), strings.HasSuffix(a, ".error"):
		return "failure"
	case strings.Contains(a, "granted"), strings.Contains(a, "approved"), strings.Contains(a, "success"), strings.HasSuffix(a, ".opened"):
		return "success"
	default:
		return ""
	}
}

func NormalizeIndex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "keeppam-audit"
	}
	return b.String()
}

func bulkURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return ""
	}
	if strings.HasSuffix(raw, "/_bulk") {
		return raw
	}
	return raw + "/_bulk"
}

// EncodeBulk writes OpenSearch/Elasticsearch _bulk NDJSON (index + doc per event).
func EncodeBulk(index string, events []store.AuditEvent) []byte {
	index = NormalizeIndex(index)
	var b strings.Builder
	for _, e := range events {
		meta, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": index, "_id": e.ID.String()}})
		doc, _ := json.Marshal(EventECS(e))
		b.Write(meta)
		b.WriteByte('\n')
		b.Write(doc)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
