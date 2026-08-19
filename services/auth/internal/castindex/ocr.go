package castindex

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
)

const (
	ocrMaxLine = 512
)

func ocrStoreCap(n int) int {
	if n <= 0 {
		return policy.OCRDefaultFrames
	}
	if n > policy.OCRMaxFramesCap {
		return policy.OCRMaxFramesCap
	}
	return n
}

type OCRResult struct {
	Indexed    bool   `json:"indexed"`
	Source     string `json:"source"`
	ScreenText int    `json:"screen_text"`
	Skipped    string `json:"skipped,omitempty"`
}

func (s *Service) IndexOCR(ctx context.Context, sessionID uuid.UUID, force bool) (OCRResult, error) {
	if s == nil || s.sess == nil {
		return OCRResult{Skipped: "unavailable"}, nil
	}
	if strings.TrimSpace(s.guacencURL) == "" {
		return OCRResult{Skipped: "no_guacenc"}, nil
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return OCRResult{}, err
	}
	if !graphicalSession(row) {
		return OCRResult{Skipped: "unsupported"}, nil
	}
	n, _ := s.sess.CountScreenText(ctx, sessionID)
	if !force && n > 0 {
		return OCRResult{Indexed: true, Source: "cached", ScreenText: n}, nil
	}
	if force {
		_ = s.sess.DeleteGuacScreenText(ctx, sessionID)
	}
	if row.RecordingPath == "" {
		return OCRResult{Indexed: true, Source: "guacenc", Skipped: "no_recording"}, nil
	}
	path, err := s.sess.RecordingFile(ctx, sessionID)
	if err != nil {
		return OCRResult{Indexed: true, Source: "guacenc", Skipped: "no_recording"}, nil
	}
	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, row.RecordingPath)
	}
	opt := policy.OCROpts{Lang: policy.OCRDefaultLang, IntervalSec: policy.OCRDefaultInterval, MaxFrames: policy.OCRDefaultFrames}
	if row.PolicySnapshot != nil {
		opt = row.PolicySnapshot.OCR()
	}
	frames, err := s.fetchOCR(ctx, path, opt)
	if err != nil {
		return OCRResult{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	var last string
	stored := 0
	dlp := contentDLP(row)
	var piiTotal outputPIIStats
	piiTotal.kinds = map[string]struct{}{}
	for _, fr := range frames {
		line := cleanOCRLine(fr.Text)
		if line == "" || line == last || stored >= ocrStoreCap(opt.MaxFrames) {
			continue
		}
		text, skip, st := applyContentDLP(dlp, line)
		if skip {
			mergePIIStats(&piiTotal, st)
			continue
		}
		if st != nil {
			mergePIIStats(&piiTotal, st)
		}
		last = line
		ts := base.Add(time.Duration(fr.Offset * float64(time.Second)))
		payload := map[string]any{"line": text, "source": "guacenc", "offset": fr.Offset}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "screen_text", payload); err != nil {
			return OCRResult{}, err
		}
		stored++
	}
	if ev := dlpPayload(&piiTotal, "screen_text"); ev != nil {
		_ = s.sess.AddEventAt(ctx, sessionID, base, "dlp", ev)
	}
	n, _ = s.sess.CountScreenText(ctx, sessionID)
	return OCRResult{Indexed: true, Source: "guacenc", ScreenText: n}, nil
}

func (s *Service) IndexOCRAsync(sessionID uuid.UUID) {
	if s == nil || strings.TrimSpace(s.guacencURL) == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		_, _ = s.IndexOCR(ctx, sessionID, false)
	}()
}

func cleanOCRLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) > ocrMaxLine {
		rs := []rune(s)
		s = string(rs[:ocrMaxLine])
	}
	return s
}
