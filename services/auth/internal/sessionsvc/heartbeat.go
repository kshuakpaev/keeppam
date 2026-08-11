package sessionsvc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Heartbeat updates last_seen_at every interval until stop is closed.
func Heartbeat(ctx context.Context, s *Service, id uuid.UUID, interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	_ = s.Touch(ctx, id)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = s.Touch(context.Background(), id)
		}
	}
}
