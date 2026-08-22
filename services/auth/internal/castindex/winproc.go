package castindex

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

type WinProcResult struct {
	Indexed  bool   `json:"indexed"`
	Count    int    `json:"count"`
	Skipped  string `json:"skipped,omitempty"`
}

func (s *Service) IndexWinProcesses(ctx context.Context, sessionID uuid.UUID, force bool) (WinProcResult, error) {
	if s == nil || s.sess == nil {
		return WinProcResult{Skipped: "unavailable"}, nil
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return WinProcResult{}, err
	}
	if row.Protocol != "rdp" && row.Protocol != "vnc" && !row.Isolated {
		return WinProcResult{Skipped: "unsupported"}, nil
	}
	n, _ := s.sess.CountWinProcesses(ctx, sessionID)
	if !force && n > 0 {
		return WinProcResult{Indexed: true, Count: n, Skipped: "cached"}, nil
	}
	if force {
		_ = s.sess.DeleteWinProcesses(ctx, sessionID)
	}
	screen, err := s.sess.ListScreenTextTranscript(ctx, sessionID)
	if err != nil {
		return WinProcResult{}, err
	}
	keys, err := s.sess.ListKeystrokeTranscript(ctx, sessionID)
	if err != nil {
		return WinProcResult{}, err
	}
	hits := sessionsvc.ExtractWinProcesses(screen, keys)
	if len(hits) == 0 {
		return WinProcResult{Indexed: true, Count: 0}, nil
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	for _, h := range hits {
		ts := base.Add(time.Duration(h.Offset * float64(time.Second)))
		payload := map[string]any{
			"name": h.Name, "source": h.Source, "confidence": h.Confidence, "offset": h.Offset,
		}
		if h.Title != "" {
			payload["title"] = h.Title
		}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "win_process", payload); err != nil {
			return WinProcResult{}, err
		}
	}
	n, _ = s.sess.CountWinProcesses(ctx, sessionID)
	return WinProcResult{Indexed: true, Count: n}, nil
}

func (s *Service) IndexWinProcessesAsync(sessionID uuid.UUID) {
	if s == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, _ = s.IndexWinProcesses(ctx, sessionID, false)
	}()
}
