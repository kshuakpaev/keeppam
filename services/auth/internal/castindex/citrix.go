package castindex

import (
	"context"
	"os"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/citrix/hdx"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func citrixSession(row sessionsvc.Session) bool {
	return row.Protocol == "citrix"
}

func (s *Service) indexCitrix(ctx context.Context, sessionID uuid.UUID, row sessionsvc.Session, force bool) (Result, error) {
	n, _ := s.sess.CountKeystrokes(ctx, sessionID)
	if !force && n > 0 {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "hdx", Keystrokes: n}, nil
	}
	indexed, _ := s.sess.TranscriptIndexed(ctx, sessionID)
	if !force && indexed {
		return Result{Indexed: true, Source: "cached", Keystrokes: n}, nil
	}
	if force {
		_ = s.sess.DeleteHDXKeystrokes(ctx, sessionID)
	}
	if row.RecordingPath == "" {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "hdx", Skipped: "no_recording"}, nil
	}
	path := row.RecordingPath
	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, row.RecordingPath)
	}
	if _, err := os.Stat(path); err != nil {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "hdx", Skipped: "no_recording"}, nil
	}
	events, err := hdx.ParseJSONL(path)
	if err != nil {
		return Result{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	stored := 0
	for _, ev := range events {
		if ev.Event != "hdx_keystroke" && ev.Event != "keystroke" {
			continue
		}
		line := hdx.MetaString(ev.Meta, "line")
		if line == "" {
			line = hdx.MetaString(ev.Meta, "text")
		}
		if line == "" {
			continue
		}
		ts := hdx.ParseTime(ev.T, base)
		payload := map[string]any{
			"line": line, "source": "hdx", "offset": hdx.MetaFloat(ev.Meta, "offset"),
		}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "keystroke", payload); err != nil {
			return Result{}, err
		}
		stored++
	}
	_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
	n, _ = s.sess.CountKeystrokes(ctx, sessionID)
	return Result{Indexed: true, Source: "hdx", Keystrokes: n, Lines: stored}, nil
}

func (s *Service) indexCitrixOCR(ctx context.Context, sessionID uuid.UUID, row sessionsvc.Session, force bool) (OCRResult, error) {
	n, _ := s.sess.CountScreenText(ctx, sessionID)
	if !force && n > 0 {
		return OCRResult{Indexed: true, Source: "cached", ScreenText: n}, nil
	}
	if force {
		_ = s.sess.DeleteHDXScreenText(ctx, sessionID)
	}
	if row.RecordingPath == "" {
		return OCRResult{Indexed: true, Source: "hdx", Skipped: "no_recording"}, nil
	}
	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, row.RecordingPath)
	}
	if _, err := os.Stat(row.RecordingPath); err != nil {
		return OCRResult{Indexed: true, Source: "hdx", Skipped: "no_recording"}, nil
	}
	events, err := hdx.ParseJSONL(row.RecordingPath)
	if err != nil {
		return OCRResult{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	var last string
	stored := 0
	for _, ev := range events {
		if ev.Event != "hdx_ocr" && ev.Event != "ocr" {
			continue
		}
		text := hdx.MetaString(ev.Meta, "text")
		if text == "" {
			text = hdx.MetaString(ev.Meta, "line")
		}
		text = cleanOCRLine(text)
		if text == "" || text == last {
			continue
		}
		last = text
		ts := hdx.ParseTime(ev.T, base)
		payload := map[string]any{
			"line": text, "source": "hdx", "offset": hdx.MetaFloat(ev.Meta, "offset"),
		}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "screen_text", payload); err != nil {
			return OCRResult{}, err
		}
		stored++
	}
	n, _ = s.sess.CountScreenText(ctx, sessionID)
	return OCRResult{Indexed: true, Source: "hdx", ScreenText: n}, nil
}
