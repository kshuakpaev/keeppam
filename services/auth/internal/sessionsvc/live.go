package sessionsvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const killChannel = "keeppam:session:kill"

// LiveHub tracks in-process session tear-down callbacks and broadcasts kills via Redis
// so API and session-worker can force-end each other's live tunnels.
type LiveHub struct {
	rdb   *redis.Client
	local sync.Map // string(id) -> func()
}

func NewLiveHub(rdb *redis.Client) *LiveHub {
	return &LiveHub{rdb: rdb}
}

func liveChan(id string) string    { return "keeppam:session:live:" + id }
func liveBufKey(id string) string { return "keeppam:session:livebuf:" + id }

type LiveEvent struct {
	Kind string `json:"k"` // out | sql | end | meta
	Data string `json:"d,omitempty"`
}

// Register stores a kill callback for a live session. Caller must invoke the returned unregister.
func (h *LiveHub) Register(id uuid.UUID, kill func()) (unregister func()) {
	if h == nil || kill == nil {
		return func() {}
	}
	key := id.String()
	h.local.Store(key, kill)
	return func() {
		h.local.Delete(key)
	}
}

// Kill publishes a force-end for the session and invokes any local callback immediately.
func (h *LiveHub) Kill(ctx context.Context, id uuid.UUID) {
	if h == nil {
		return
	}
	h.invokeLocal(id.String())
	h.Fanout(ctx, id, "end", "")
	if h.rdb != nil {
		if err := h.rdb.Publish(ctx, killChannel, id.String()).Err(); err != nil {
			slog.Warn("session kill publish", "id", id.String(), "err", err)
		}
	}
}

// Fanout publishes a live event to watchers (best-effort).
func (h *LiveHub) Fanout(ctx context.Context, id uuid.UUID, kind, data string) {
	if h == nil || h.rdb == nil {
		return
	}
	raw, _ := json.Marshal(LiveEvent{Kind: kind, Data: data})
	sid := id.String()
	go func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if kind == "out" && data != "" {
			if b, err := base64.StdEncoding.DecodeString(data); err == nil {
				h.appendBuf(c, sid, b)
			}
		}
		if err := h.rdb.Publish(c, liveChan(sid), raw).Err(); err != nil {
			slog.Debug("live fanout", "id", sid, "err", err)
		}
	}()
}

func (h *LiveHub) FanoutOutput(ctx context.Context, id uuid.UUID, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	h.Fanout(ctx, id, "out", base64.StdEncoding.EncodeToString(chunk))
}

func (h *LiveHub) FanoutSQL(ctx context.Context, id uuid.UUID, payload any) {
	if h == nil {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	h.Fanout(ctx, id, "sql", string(raw))
}

func (h *LiveHub) appendBuf(ctx context.Context, sid string, chunk []byte) {
	const max = 48 * 1024
	key := liveBufKey(sid)
	prev, _ := h.rdb.Get(ctx, key).Bytes()
	buf := append(append([]byte{}, prev...), chunk...)
	if len(buf) > max {
		buf = buf[len(buf)-max:]
	}
	_ = h.rdb.Set(ctx, key, buf, 8*time.Hour).Err()
}

func (h *LiveHub) Snapshot(ctx context.Context, id uuid.UUID) []byte {
	if h == nil || h.rdb == nil {
		return nil
	}
	b, err := h.rdb.Get(ctx, liveBufKey(id.String())).Bytes()
	if err != nil {
		return nil
	}
	return b
}

func (h *LiveHub) Clear(ctx context.Context, id uuid.UUID) {
	if h == nil || h.rdb == nil {
		return
	}
	_ = h.rdb.Del(ctx, liveBufKey(id.String())).Err()
}

// Subscribe yields live events until ctx is cancelled.
func (h *LiveHub) Subscribe(ctx context.Context, id uuid.UUID) (<-chan LiveEvent, func()) {
	out := make(chan LiveEvent, 64)
	noop := func() {}
	if h == nil || h.rdb == nil {
		close(out)
		return out, noop
	}
	sub := h.rdb.Subscribe(ctx, liveChan(id.String()))
	ch := sub.Channel()
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				if msg == nil {
					continue
				}
				var ev LiveEvent
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, func() { _ = sub.Close() }
}

// Listen subscribes to kill broadcasts until ctx is cancelled.
func (h *LiveHub) Listen(ctx context.Context) {
	if h == nil || h.rdb == nil {
		return
	}
	sub := h.rdb.Subscribe(ctx, killChannel)
	defer sub.Close()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if msg != nil && msg.Payload != "" {
				h.invokeLocal(msg.Payload)
			}
		}
	}
}

func (h *LiveHub) invokeLocal(id string) {
	if v, ok := h.local.Load(id); ok {
		if fn, ok := v.(func()); ok {
			fn()
		}
	}
}
