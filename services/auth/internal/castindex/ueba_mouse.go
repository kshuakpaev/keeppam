package castindex

import (
	"context"
	"log/slog"
	"time"

	"github.com/keeppam/auth/internal/guacindex"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/ueba"
)

func (s *Service) evaluateMouseUEBA(ctx context.Context, row sessionsvc.Session, tim guacindex.MouseTiming) {
	if s == nil || s.sess == nil || tim.NMoves < ueba.MinMouseMoves || tim.Samples < ueba.MinMouseSamples || tim.MedianVel <= 0 {
		return
	}
	statsPayload := map[string]any{
		"factor":            ueba.FactorMouseStats,
		"median_vel_px_ms":  round1(tim.MedianVel),
		"mean_vel_px_ms":    round1(tim.MeanVel),
		"n_moves":           tim.NMoves,
		"samples":           tim.Samples,
		"source":            "guac",
	}
	_ = s.sess.AddEvent(ctx, row.ID, "ueba", statsPayload)

	since := ueba.BaselineFrom(time.Now())
	vels, err := s.sess.MouseVelMedians(ctx, row.UserID, since, row.ID)
	if err != nil {
		slog.Warn("ueba mouse baseline", "err", err, "session", row.ID.String())
		return
	}
	mean, std := ueba.MeanStd(vels)
	z := ueba.ZScore(tim.MedianVel, mean, std)
	if !ueba.FastMouse(tim.MedianVel, tim.NMoves, tim.Samples, len(vels), mean, std, z) {
		return
	}
	score, factors, err := s.sess.AppendRisk(ctx, row.ID, ueba.MouseFastPoints, ueba.FactorMouseFast)
	if err != nil {
		slog.Warn("ueba mouse risk", "err", err)
		return
	}
	payload := map[string]any{
		"factor":            ueba.FactorMouseFast,
		"median_vel_px_ms":  round1(tim.MedianVel),
		"baseline_mean":     round1(mean),
		"baseline_std":      round1(std),
		"baseline_n":        len(vels),
		"z":                 round1(z),
		"n_moves":           tim.NMoves,
		"samples":           tim.Samples,
		"risk_score":        score,
		"risk_factors":      factors,
		"source":            "guac",
	}
	_ = s.sess.AddEvent(ctx, row.ID, "risk", payload)
	_ = s.sess.AddEvent(ctx, row.ID, "ueba", payload)
	if s.uebaHook != nil {
		s.uebaHook(ctx, row, payload)
	}
}
