package tn3270

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/sessionsvc"
)

// BridgeOpts configures recording / event indexing during relay.
type BridgeOpts struct {
	RecordingPath string
	SessionID     uuid.UUID
	Sessions      *sessionsvc.Service
	Codepage      Codepage
}

// Bridge transparently relays TN3270 EOR frames between client and host.
func Bridge(ctx context.Context, client, host net.Conn, opts BridgeOpts) error {
	if opts.Codepage == "" {
		opts.Codepage = CP037
	}
	rec, err := openRecorder(opts.RecordingPath)
	if err != nil {
		return err
	}
	defer rec.Close()

	errCh := make(chan error, 2)
	var once sync.Once
	fail := func(e error) {
		once.Do(func() {
			if e == nil {
				e = io.EOF
			}
			errCh <- e
		})
	}

	go pipeDir(ctx, host, client, "down", rec, opts, fail)
	go pipeDir(ctx, client, host, "up", rec, opts, fail)

	select {
	case <-ctx.Done():
		_ = client.Close()
		_ = host.Close()
		return ctx.Err()
	case e := <-errCh:
		_ = client.Close()
		_ = host.Close()
		if e == io.EOF {
			return nil
		}
		return e
	}
}

func pipeDir(ctx context.Context, src, dst net.Conn, dir string, rec *recorder, opts BridgeOpts, fail func(error)) {
	buf := make([]byte, 64*1024)
	pending := []byte(nil)
	for {
		select {
		case <-ctx.Done():
			fail(ctx.Err())
			return
		default:
		}
		_ = src.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, werr := dst.Write(chunk); werr != nil {
				fail(werr)
				return
			}
			pending = append(pending, chunk...)
			frames, rest := SplitEOR(pending)
			pending = rest
			for _, fr := range frames {
				text := ExtractScreenText(fr, opts.Codepage)
				rec.write(dir, len(fr), text)
				if text != "" && opts.Sessions != nil && opts.SessionID != uuid.Nil {
					_ = opts.Sessions.AddEvent(context.Background(), opts.SessionID, "screen_text", map[string]any{
						"dir":       dir,
						"text":      text,
						"proto":     "tn3270",
						"codepage":  string(NormalizeCodepage(string(opts.Codepage))),
					})
				}
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			fail(err)
			return
		}
	}
}

type recorder struct {
	f     *os.File
	enc   *json.Encoder
	start time.Time
	mu    sync.Mutex
}

func openRecorder(path string) (*recorder, error) {
	if path == "" {
		return &recorder{start: time.Now()}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, err
	}
	return &recorder{f: f, enc: json.NewEncoder(f), start: time.Now()}, nil
}

func (r *recorder) write(dir string, n int, text string) {
	if r == nil || r.enc == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.enc.Encode(map[string]any{
		"t":    time.Since(r.start).Seconds(),
		"dir":  dir,
		"n":    n,
		"text": text,
	})
}

func (r *recorder) Close() {
	if r != nil && r.f != nil {
		_ = r.f.Close()
	}
}
