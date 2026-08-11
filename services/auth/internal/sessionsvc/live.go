package sessionsvc

import (
	"context"
	"log/slog"
	"sync"

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
	if h.rdb != nil {
		if err := h.rdb.Publish(ctx, killChannel, id.String()).Err(); err != nil {
			slog.Warn("session kill publish", "id", id.String(), "err", err)
		}
	}
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
