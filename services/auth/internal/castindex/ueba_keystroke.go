package castindex

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/keeppam/auth/internal/guacindex"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/ueba"
	"github.com/keeppam/auth/internal/uebaml"
)

// UEBAHook is called when post-session keystroke timing looks anomalous.
type UEBAHook func(ctx context.Context, row sessionsvc.Session, payload map[string]any)

func (s *Service) SetUEBAHook(h UEBAHook) {
	if s != nil {
		s.uebaHook = h
	}
}

func (s *Service) SetUEBAML(sc UEBAMLScorer) {
	if s != nil {
		s.uebaml = sc
	}
}

func (s *Service) evaluateKeystrokeUEBA(ctx context.Context, row sessionsvc.Session, tim guacindex.Timing) {
	if s == nil || s.sess == nil || tim.NKeys < ueba.MinKeystrokeKeys || tim.MedianMs <= 0 {
		return
	}
	statsPayload := map[string]any{
		"factor":         ueba.FactorKeystrokeStats,
		"median_iki_ms":  round1(tim.MedianMs),
		"mean_iki_ms":    round1(tim.MeanMs),
		"n_keys":         tim.NKeys,
		"intervals":      tim.Intervals,
		"source":         "guac",
	}
	_ = s.sess.AddEvent(ctx, row.ID, "ueba", statsPayload)

	since := ueba.BaselineFrom(time.Now())
	medians, err := s.sess.KeystrokeMedians(ctx, row.UserID, since, row.ID)
	if err != nil {
		slog.Warn("ueba keystroke baseline", "err", err, "session", row.ID.String())
		return
	}
	mean, std := ueba.MeanStd(medians)
	z := ueba.ZScore(tim.MedianMs, mean, std)
	if s.uebaml != nil && s.uebaml.Enabled(ctx) {
		if ml, extras := s.uebaml.ScorePostSession(ctx, row, z, 0); len(extras) > 0 {
			for _, f := range extras {
				score, factors, err := s.sess.AppendRisk(ctx, row.ID, uebamlMLPoints(f), f)
				if err == nil {
					_ = s.sess.AddEvent(ctx, row.ID, "ueba", map[string]any{
						"factor": f, "ml_score": ml, "source": "uebaml", "risk_score": score, "risk_factors": factors,
					})
				}
			}
		}
	}
	if !ueba.FastTyping(tim.MedianMs, tim.NKeys, len(medians), mean, std, z) {
		return
	}
	score, factors, err := s.sess.AppendRisk(ctx, row.ID, ueba.KeystrokeFastPoints, ueba.FactorKeystrokeFast)
	if err != nil {
		slog.Warn("ueba keystroke risk", "err", err)
		return
	}
	payload := map[string]any{
		"factor":            ueba.FactorKeystrokeFast,
		"median_iki_ms":     round1(tim.MedianMs),
		"baseline_mean_ms":  round1(mean),
		"baseline_std_ms":   round1(std),
		"baseline_n":        len(medians),
		"z":                 round1(z),
		"n_keys":            tim.NKeys,
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

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func uebamlMLPoints(f string) int {
	switch f {
	case uebaml.FactorMLHigh:
		return uebaml.MLHighPoints
	default:
		return 15
	}
}
