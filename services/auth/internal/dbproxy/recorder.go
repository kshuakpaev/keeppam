package dbproxy

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Recorder writes NDJSON SQL statements for session replay.
type Recorder struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
}

func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	r := &Recorder{f: f, start: time.Now().UTC()}
	_ = r.write(map[string]any{
		"type": "header", "version": 1, "format": "keeppam-sql", "started_at": r.start.Format(time.RFC3339Nano),
	})
	return r, nil
}

func (r *Recorder) Record(statement string, durationMs int64, rowCount int, errMsg string) {
	if r == nil {
		return
	}
	payload := map[string]any{
		"type": "sql",
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"sec":  time.Since(r.start).Seconds(),
		"statement": truncateStmt(statement),
		"duration_ms": durationMs,
		"row_count": rowCount,
	}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	_ = r.write(payload)
}

func (r *Recorder) Close() error {
	if r == nil || r.f == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

func (r *Recorder) write(v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = r.f.Write(append(b, '\n'))
	return err
}

func truncateStmt(s string) string {
	const max = 8000
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
