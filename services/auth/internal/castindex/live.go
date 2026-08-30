package castindex

import (
	"context"
	"log/slog"
	"time"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
)

const liveOCRTick = 20 * time.Second

// RunLive incrementally OCRs active RDP/VNC recordings and indexes SSH/Telnet stdout
// before the session ends.
func (s *Service) RunLive(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(liveOCRTick)
	defer ticker.Stop()
	s.liveTick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.liveTick(ctx)
		}
	}
}

func (s *Service) liveTick(ctx context.Context) {
	if s.sess == nil {
		return
	}
	rows, _, err := s.sess.List(ctx, sessionsvc.ListFilter{Status: "active", Limit: 200})
	if err != nil {
		slog.Warn("ocr live list", "err", err)
		return
	}
	for _, row := range rows {
		if row.RecordingPath == "" {
			continue
		}
		opt := policy.OCROpts{SSHStdout: true}
		if row.PolicySnapshot != nil {
			opt = row.PolicySnapshot.OCR()
		}
		tickCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		switch {
		case graphicalSession(row) && opt.Live:
			if _, err := s.IndexOCR(tickCtx, row.ID, false); err != nil {
				slog.Warn("ocr live", "session", row.ID.String(), "err", err)
			}
		case (row.Protocol == "ssh" || row.Protocol == "telnet") && opt.SSHStdout:
			if _, err := s.Index(tickCtx, row.ID, false); err != nil {
				slog.Warn("ssh stdout live", "session", row.ID.String(), "err", err)
			}
		}
		cancel()
	}
}
