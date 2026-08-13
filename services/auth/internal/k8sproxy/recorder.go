package k8sproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Recorder struct {
	mu   sync.Mutex
	file *os.File
}

func NewRecorder(path string, sessionID uuid.UUID) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	rec := &Recorder{file: f}
	_ = rec.write(map[string]any{
		"type":       "header",
		"format":     "keeppam-k8s",
		"version":    1,
		"session_id": sessionID.String(),
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rec, nil
}

func (r *Recorder) WriteCall(call APICall, method, path string, status int) {
	if r == nil {
		return
	}
	_ = r.write(map[string]any{
		"type":          "k8s",
		"ts":            time.Now().UTC().Format(time.RFC3339Nano),
		"method":        method,
		"path":          path,
		"verb":          call.Verb,
		"api_group":     call.APIGroup,
		"resource":      call.Resource,
		"namespace":     call.Namespace,
		"name":          call.Name,
		"subresource":   call.Subresource,
		"watch":         call.Watch,
		"status":        status,
		"body_redacted": true,
	})
}

func (r *Recorder) write(v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = r.file.Write(append(b, '\n'))
	return err
}

func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
}
