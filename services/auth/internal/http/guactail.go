package httpapi

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) tailGuacRecording(ctx context.Context, id uuid.UUID, protocol string, writeJSON func(any) error) {
	var path string
	deadline := time.Now().Add(2 * time.Minute)
	for path == "" {
		if ctx.Err() != nil {
			return
		}
		p, err := s.sessionsvc.RecordingFile(ctx, id)
		if err == nil && p != "" && sessionsvc.IsGuacamoleRecording(protocol, p) {
			path = p
			break
		}
		if time.Now().After(deadline) {
			_ = writeJSON(map[string]any{"type": "guac_unavailable"})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
	}
	f, err := os.Open(path)
	if err != nil {
		_ = writeJSON(map[string]any{"type": "guac_unavailable"})
		return
	}
	defer f.Close()
	buf := make([]byte, 32*1024)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	idle := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := f.Read(buf)
				if n > 0 {
					idle = 0
					if werr := writeJSON(map[string]any{
						"type":  "guac",
						"chunk": base64.StdEncoding.EncodeToString(buf[:n]),
					}); werr != nil {
						return
					}
				}
				if err == io.EOF {
					idle++
					if idle > 1500 { // ~5 min without new bytes
						return
					}
					break
				}
				if err != nil {
					return
				}
			}
		}
	}
}
