package castindex

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/sessionsvc"
)

type Service struct {
	sess  *sessionsvc.Service
	store recstore.Store
}

func New(sess *sessionsvc.Service, store recstore.Store) *Service {
	return &Service{sess: sess, store: store}
}

type Result struct {
	Indexed bool   `json:"indexed"`
	Source  string `json:"source"`
	Lines   int    `json:"lines"`
	Skipped string `json:"skipped,omitempty"`
}

// Index extracts SSH stdin from the asciicast unless PTY JEA already logged commands.
func (s *Service) Index(ctx context.Context, sessionID uuid.UUID, force bool) (Result, error) {
	if s == nil || s.sess == nil {
		return Result{Skipped: "unavailable"}, nil
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return Result{}, err
	}
	if row.Protocol != "ssh" {
		return Result{Skipped: "not_ssh"}, nil
	}
	if lines, err := s.sess.ListCommandTranscript(ctx, sessionID); err == nil && ptyLogged(lines) {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "pty", Lines: len(lines)}, nil
	}
	if !force {
		if ok, err := s.sess.TranscriptIndexed(ctx, sessionID); err == nil && ok {
			n, _ := s.sess.ListCommandTranscript(ctx, sessionID)
			return Result{Indexed: true, Source: "cached", Lines: len(n)}, nil
		}
	} else {
		_ = s.sess.DeleteAsciicastCommands(ctx, sessionID)
	}
	if row.RecordingPath == "" {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Skipped: "no_recording"}, nil
	}
	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, row.RecordingPath)
	}
	f, err := os.Open(row.RecordingPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	lines, err := InputLines(f)
	if err != nil {
		return Result{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	n := 0
	for _, ln := range lines {
		ts := base.Add(time.Duration(ln.Offset * float64(time.Second)))
		payload := map[string]any{"command": ln.Text, "source": "asciicast", "offset": ln.Offset}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "command", payload); err != nil {
			return Result{Lines: n}, err
		}
		n++
	}
	_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
	return Result{Indexed: true, Source: "asciicast", Lines: n}, nil
}

func ptyLogged(lines []sessionsvc.TranscriptLine) bool {
	for _, ln := range lines {
		if ln.Source == "pty" || ln.Type == "command_denied" || ln.Type == "command_approval" || ln.Type == "command_approved" {
			return true
		}
	}
	return false
}

func (s *Service) IndexAsync(sessionID uuid.UUID) {
	if s == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = s.Index(ctx, sessionID, false)
	}()
}
