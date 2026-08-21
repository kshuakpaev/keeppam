package hdx

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// SessionEvents is the subset of sessionsvc used when finalizing HDX recording.
type SessionEvents interface {
	GetRecordingPath(ctx context.Context, sessionID uuid.UUID) (string, time.Time, error)
	AddEventAt(ctx context.Context, sessionID uuid.UUID, ts time.Time, eventType string, payload map[string]any) error
}

// Finalize syncs remaining plugin events into JSONL/session events, stops the plugin, clears Redis.
func Finalize(ctx context.Context, rdb *redis.Client, client *Client, sink SessionEvents, sessionID uuid.UUID, ttl time.Duration) {
	if client == nil || !client.Enabled() || rdb == nil || sink == nil {
		return
	}
	b, err := GetBinding(ctx, rdb, sessionID)
	if err != nil {
		return
	}
	recPath, base, err := sink.GetRecordingPath(ctx, sessionID)
	if err != nil {
		recPath = ""
		base = time.Now().UTC()
	}
	if st, err := client.Status(ctx, b.PluginSessionID); err == nil {
		_, _ = ApplyEvents(ctx, rdb, sink, sessionID, recPath, base, st.Events, ttl)
	}
	_ = client.Stop(ctx, b.PluginSessionID)
	ClearBinding(ctx, rdb, sessionID)
}

// ApplyEvents writes plugin recording events to JSONL and forensic session_events (dedup by seq).
func ApplyEvents(ctx context.Context, rdb *redis.Client, sink SessionEvents, sessionID uuid.UUID, recPath string, base time.Time, events []RecordingEvt, ttl time.Duration) (int, error) {
	last := LastSeq(ctx, rdb, sessionID)
	accepted := 0
	maxSeq := last
	for _, raw := range events {
		ev := NormalizeEvt(raw)
		if ev.Event == "" {
			continue
		}
		if ev.Seq > 0 && ev.Seq <= last {
			continue
		}
		_ = AppendJSONL(recPath, ev)
		if sink != nil {
			ts := ParseTime(ev.T, base)
			switch ev.Event {
			case "hdx_ocr", "ocr":
				text := MetaString(ev.Meta, "text")
				if text == "" {
					text = MetaString(ev.Meta, "line")
				}
				if text != "" {
					_ = sink.AddEventAt(ctx, sessionID, ts, "screen_text", map[string]any{
						"line": text, "source": "hdx", "offset": MetaFloat(ev.Meta, "offset"),
					})
				}
			case "hdx_keystroke", "keystroke":
				line := MetaString(ev.Meta, "line")
				if line == "" {
					line = MetaString(ev.Meta, "text")
				}
				if line != "" {
					_ = sink.AddEventAt(ctx, sessionID, ts, "keystroke", map[string]any{
						"line": line, "source": "hdx", "offset": MetaFloat(ev.Meta, "offset"),
					})
				}
			case "hdx_frame", "frame":
				_ = sink.AddEventAt(ctx, sessionID, ts, "citrix_frame", map[string]any{
					"source": "hdx", "seq": ev.Seq, "meta": ev.Meta,
				})
			case "hdx_started", "hdx_meta", "hdx_ended":
				name := "citrix_" + strings.TrimPrefix(ev.Event, "hdx_")
				_ = sink.AddEventAt(ctx, sessionID, ts, name, map[string]any{"source": "hdx", "meta": ev.Meta})
			}
		}
		accepted++
		if ev.Seq > maxSeq {
			maxSeq = ev.Seq
		}
	}
	if maxSeq > last {
		SetLastSeq(ctx, rdb, sessionID, maxSeq, ttl)
	}
	return accepted, nil
}
