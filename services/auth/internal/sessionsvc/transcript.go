package sessionsvc

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

type TranscriptLine struct {
	TS        time.Time `json:"ts"`
	Type      string    `json:"type"`
	Command   string    `json:"command"`
	Source    string    `json:"source,omitempty"`
	Offset    float64   `json:"offset,omitempty"`
	Filename  string    `json:"filename,omitempty"`
	FileID    string    `json:"file_id,omitempty"`
	Path      string    `json:"path,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Captured  *bool     `json:"captured,omitempty"`
}

func (s *Service) HasTypedCommands(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_events
		WHERE session_id=$1 AND event_type IN ('command','command_denied','command_approval','command_approved')`,
		sessionID).Scan(&n)
	return n > 0, err
}

func (s *Service) TranscriptIndexed(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	var indexed bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT transcript_indexed_at IS NOT NULL FROM sessions WHERE id=$1`, sessionID).Scan(&indexed)
	return indexed, err
}

func (s *Service) DeleteAsciicastCommands(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		DELETE FROM session_events
		WHERE session_id=$1 AND event_type='command' AND COALESCE(payload->>'source','')='asciicast'`, sessionID)
	return err
}

func (s *Service) DeleteAsciicastOutput(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		DELETE FROM session_events
		WHERE session_id=$1 AND event_type='output' AND COALESCE(payload->>'source','')='asciicast'`, sessionID)
	return err
}

func (s *Service) CountOutput(ctx context.Context, sessionID uuid.UUID) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_events WHERE session_id=$1 AND event_type='output'`, sessionID).Scan(&n)
	return n, err
}

func (s *Service) DeleteGuacKeystrokes(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		DELETE FROM session_events
		WHERE session_id=$1 AND event_type='keystroke' AND COALESCE(payload->>'source','')='guac'`, sessionID)
	return err
}

func (s *Service) CountKeystrokes(ctx context.Context, sessionID uuid.UUID) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_events WHERE session_id=$1 AND event_type='keystroke'`, sessionID).Scan(&n)
	return n, err
}

func (s *Service) DeleteGuacScreenText(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		DELETE FROM session_events
		WHERE session_id=$1 AND event_type='screen_text' AND COALESCE(payload->>'source','')='guacenc'`, sessionID)
	return err
}

func (s *Service) CountScreenText(ctx context.Context, sessionID uuid.UUID) (int, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_events WHERE session_id=$1 AND event_type='screen_text'`, sessionID).Scan(&n)
	return n, err
}

func (s *Service) MarkTranscriptIndexed(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET transcript_indexed_at=NOW() WHERE id=$1`, sessionID)
	return err
}

func (s *Service) ListCommandTranscript(ctx context.Context, sessionID uuid.UUID) ([]TranscriptLine, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ts, event_type, payload FROM session_events
		WHERE session_id=$1 AND event_type IN ('command','command_denied','command_approval','command_approved')
		ORDER BY ts ASC
		LIMIT 500`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TranscriptLine
	for rows.Next() {
		var line TranscriptLine
		var raw []byte
		if err := rows.Scan(&line.TS, &line.Type, &raw); err != nil {
			return nil, err
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		line.Command = payloadString(p, "command")
		line.Source = payloadString(p, "source")
		if v, ok := p["offset"].(float64); ok {
			line.Offset = v
		}
		out = append(out, line)
	}
	if out == nil {
		out = []TranscriptLine{}
	}
	return out, rows.Err()
}

func (s *Service) ListOutputTranscript(ctx context.Context, sessionID uuid.UUID) ([]TranscriptLine, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ts, event_type, payload FROM session_events
		WHERE session_id=$1 AND event_type='output'
		ORDER BY ts ASC
		LIMIT 500`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TranscriptLine
	for rows.Next() {
		var line TranscriptLine
		var raw []byte
		if err := rows.Scan(&line.TS, &line.Type, &raw); err != nil {
			return nil, err
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		line.Command = payloadString(p, "line")
		if line.Command == "" {
			line.Command = payloadString(p, "command")
		}
		line.Source = payloadString(p, "source")
		if v, ok := p["offset"].(float64); ok {
			line.Offset = v
		}
		out = append(out, line)
	}
	if out == nil {
		out = []TranscriptLine{}
	}
	return out, rows.Err()
}

func (s *Service) ListKeystrokeTranscript(ctx context.Context, sessionID uuid.UUID) ([]TranscriptLine, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ts, event_type, payload FROM session_events
		WHERE session_id=$1 AND event_type='keystroke'
		ORDER BY ts ASC
		LIMIT 500`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TranscriptLine
	for rows.Next() {
		var line TranscriptLine
		var raw []byte
		if err := rows.Scan(&line.TS, &line.Type, &raw); err != nil {
			return nil, err
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		line.Command = payloadString(p, "line")
		if line.Command == "" {
			line.Command = payloadString(p, "command")
		}
		line.Source = payloadString(p, "source")
		if v, ok := p["offset"].(float64); ok {
			line.Offset = v
		}
		out = append(out, line)
	}
	if out == nil {
		out = []TranscriptLine{}
	}
	return out, rows.Err()
}

func (s *Service) ListScreenTextTranscript(ctx context.Context, sessionID uuid.UUID) ([]TranscriptLine, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT ts, event_type, payload FROM session_events
		WHERE session_id=$1 AND event_type='screen_text'
		ORDER BY ts ASC
		LIMIT 500`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TranscriptLine
	for rows.Next() {
		var line TranscriptLine
		var raw []byte
		if err := rows.Scan(&line.TS, &line.Type, &raw); err != nil {
			return nil, err
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		line.Command = payloadString(p, "line")
		line.Source = payloadString(p, "source")
		if v, ok := p["offset"].(float64); ok {
			line.Offset = v
		}
		out = append(out, line)
	}
	if out == nil {
		out = []TranscriptLine{}
	}
	return out, rows.Err()
}

func (s *Service) ListFileTranscript(ctx context.Context, sessionID uuid.UUID) ([]TranscriptLine, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT e.ts, e.event_type, e.payload,
			EXTRACT(EPOCH FROM (e.ts - s.created_at))::float8
		FROM session_events e
		JOIN sessions s ON s.id = e.session_id
		WHERE e.session_id=$1 AND e.event_type='file_transfer'
		ORDER BY e.ts ASC
		LIMIT 200`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TranscriptLine
	for rows.Next() {
		var line TranscriptLine
		var raw []byte
		var elapsed float64
		if err := rows.Scan(&line.TS, &line.Type, &raw, &elapsed); err != nil {
			return nil, err
		}
		var p map[string]any
		_ = json.Unmarshal(raw, &p)
		line.Filename = payloadString(p, "filename")
		if line.Filename == "" {
			line.Filename = payloadString(p, "path")
		}
		line.Command = EventSnippet("file_transfer", p)
		line.Path = payloadString(p, "path")
		line.Direction = payloadString(p, "direction")
		line.Protocol = payloadString(p, "protocol")
		line.FileID = payloadString(p, "file_id")
		line.Source = "file_transfer"
		if v, ok := p["captured"].(bool); ok {
			line.Captured = &v
		}
		if v, ok := p["offset"].(float64); ok && v > 0 {
			line.Offset = v
		} else if elapsed > 0 {
			line.Offset = elapsed
		}
		out = append(out, line)
	}
	if out == nil {
		out = []TranscriptLine{}
	}
	return out, rows.Err()
}

func WindowTitleFromOCR(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if i := strings.IndexAny(line, "\n\r"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	r := []rune(line)
	if len(r) < 2 || len(r) > 96 {
		return ""
	}
	return string(r)
}

func WindowTitlesFromScreen(lines []TranscriptLine) []TranscriptLine {
	var out []TranscriptLine
	prev := ""
	for _, ln := range lines {
		title := WindowTitleFromOCR(ln.Command)
		if title == "" || strings.EqualFold(title, prev) {
			continue
		}
		prev = title
		out = append(out, TranscriptLine{
			TS: ln.TS, Type: "window_title", Command: title, Offset: ln.Offset, Source: "ocr",
		})
	}
	if out == nil {
		return []TranscriptLine{}
	}
	return out
}
