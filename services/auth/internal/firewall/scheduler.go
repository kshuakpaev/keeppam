package firewall

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

const settingsPoll = 5 * time.Minute

// RunProbeScheduler runs drift probes when probe_interval_hours > 0.
func (s *Service) RunProbeScheduler(ctx context.Context) {
	for {
		wait := settingsPoll
		cfg, _, err := s.loadSettings(ctx)
		if err == nil && cfg.ProbeIntervalHours > 0 {
			wait = time.Duration(cfg.ProbeIntervalHours) * time.Hour
			rep, err := s.Probe(ctx, uuid.Nil, "", "keeppam-scheduler")
			if err != nil {
				slog.Warn("firewall scheduled probe", "err", err)
			} else {
				slog.Info("firewall scheduled probe", "reachable", rep.ReachableCount, "total", len(rep.Results))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
