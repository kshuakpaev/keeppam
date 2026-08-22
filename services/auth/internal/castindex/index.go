package castindex

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/guacindex"
	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/termcharset"
)

type Service struct {
	sess       *sessionsvc.Service
	store      recstore.Store
	guacencURL string
	uebaHook   UEBAHook
	uebaml     UEBAMLScorer
}

// UEBAMLScorer adds peer-group + ML layer (SOW-UEBA-ML).
type UEBAMLScorer interface {
	Enabled(ctx context.Context) bool
	ScorePostSession(ctx context.Context, row sessionsvc.Session, ikiZ, mouseZ float64) (mlScore float64, extraFactors []string)
}

func New(sess *sessionsvc.Service, store recstore.Store, guacencURL string) *Service {
	return &Service{sess: sess, store: store, guacencURL: strings.TrimSpace(guacencURL)}
}

type Result struct {
	Indexed    bool   `json:"indexed"`
	Source     string `json:"source"`
	Lines      int    `json:"lines"`
	Output     int    `json:"output"`
	Keystrokes int    `json:"keystrokes,omitempty"`
	Skipped    string `json:"skipped,omitempty"`
}

// Index extracts SSH stdin (unless PTY JEA already logged commands) and stdout from the asciicast.
func (s *Service) Index(ctx context.Context, sessionID uuid.UUID, force bool) (Result, error) {
	if s == nil || s.sess == nil {
		return Result{Skipped: "unavailable"}, nil
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return Result{}, err
	}
	if graphicalSession(row) {
		return s.indexGuac(ctx, sessionID, row, force)
	}
	if citrixSession(row) {
		return s.indexCitrix(ctx, sessionID, row, force)
	}
	if row.Protocol != "ssh" {
		return Result{Skipped: "unsupported"}, nil
	}
	cmdLines, err := s.sess.ListCommandTranscript(ctx, sessionID)
	if err != nil {
		return Result{}, err
	}
	pty := ptyLogged(cmdLines)
	hasCastCmd := false
	for _, ln := range cmdLines {
		if ln.Source == "asciicast" {
			hasCastCmd = true
			break
		}
	}
	outN, _ := s.sess.CountOutput(ctx, sessionID)
	indexed, _ := s.sess.TranscriptIndexed(ctx, sessionID)
	needCmd := !pty && (force || !hasCastCmd)
	needOut := force || outN == 0
	if !force && indexed && !needCmd && !needOut {
		return Result{Indexed: true, Source: "cached", Lines: len(cmdLines), Output: outN}, nil
	}

	if force {
		_ = s.sess.DeleteAsciicastCommands(ctx, sessionID)
		_ = s.sess.DeleteAsciicastOutput(ctx, sessionID)
		needCmd = !pty
		needOut = true
	}

	if row.RecordingPath == "" {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return s.result(ctx, sessionID, pty, "no_recording")
	}
	if !needCmd && !needOut {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return s.result(ctx, sessionID, pty, "")
	}

	if s.store != nil {
		_ = s.store.EnsureLocal(ctx, row.RecordingPath)
	}
	f, err := os.Open(row.RecordingPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	inLines, outLines, err := ParseCast(f)
	if err != nil {
		return Result{}, err
	}
	cs := sessionCharset(row)
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	if needCmd {
		for _, ln := range inLines {
			text, meta := indexText(ln.Text, cs)
			ts := base.Add(time.Duration(ln.Offset * float64(time.Second)))
			payload := map[string]any{"command": text, "source": "asciicast", "offset": ln.Offset, "charset": meta.Charset}
			if meta.RawB64 != "" {
				payload["raw"] = meta.RawB64
			}
			if err := s.sess.AddEventAt(ctx, sessionID, ts, "command", payload); err != nil {
				return Result{}, err
			}
		}
	}
	if needOut {
		dlp := contentDLP(row)
		var piiTotal outputPIIStats
		piiTotal.kinds = map[string]struct{}{}
		for _, ln := range outLines {
			text, meta := indexText(ln.Text, cs)
			text, skip, st := applyContentDLP(dlp, text)
			if skip {
				mergePIIStats(&piiTotal, st)
				continue
			}
			if st != nil {
				mergePIIStats(&piiTotal, st)
			}
			ts := base.Add(time.Duration(ln.Offset * float64(time.Second)))
			payload := map[string]any{"line": text, "source": "asciicast", "offset": ln.Offset, "charset": meta.Charset}
			if meta.RawB64 != "" {
				payload["raw"] = meta.RawB64
			}
			if err := s.sess.AddEventAt(ctx, sessionID, ts, "output", payload); err != nil {
				return Result{}, err
			}
		}
		if ev := dlpPayload(&piiTotal, "ssh_stdout"); ev != nil {
			_ = s.sess.AddEventAt(ctx, sessionID, base, "dlp", ev)
		}
	}
	_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
	return s.result(ctx, sessionID, pty, "")
}

func sessionCharset(row sessionsvc.Session) string {
	if row.PolicySnapshot != nil && row.PolicySnapshot.TerminalCharset != "" {
		return termcharset.Normalize(row.PolicySnapshot.TerminalCharset)
	}
	return termcharset.UTF8
}

// indexText: cast is usually already UTF-8 (recorder decoded); re-decode only if needed.
func indexText(s, charset string) (string, termcharset.Result) {
	meta := termcharset.DecodeString(s, charset)
	return meta.Text, meta
}

func (s *Service) result(ctx context.Context, sessionID uuid.UUID, pty bool, skipped string) (Result, error) {
	cmds, _ := s.sess.ListCommandTranscript(ctx, sessionID)
	outN, _ := s.sess.CountOutput(ctx, sessionID)
	src := "asciicast"
	if pty {
		src = "pty"
	}
	return Result{Indexed: true, Source: src, Lines: len(cmds), Output: outN, Skipped: skipped}, nil
}

func graphicalSession(row sessionsvc.Session) bool {
	return row.Protocol == "rdp" || row.Protocol == "vnc" || row.Isolated
}

func (s *Service) indexGuac(ctx context.Context, sessionID uuid.UUID, row sessionsvc.Session, force bool) (Result, error) {
	n, _ := s.sess.CountKeystrokes(ctx, sessionID)
	indexed, _ := s.sess.TranscriptIndexed(ctx, sessionID)
	if !force && indexed && n > 0 {
		return Result{Indexed: true, Source: "cached", Keystrokes: n}, nil
	}
	if force {
		_ = s.sess.DeleteGuacKeystrokes(ctx, sessionID)
	}
	if row.RecordingPath == "" {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "guac", Skipped: "no_recording"}, nil
	}
	path, err := s.sess.RecordingFile(ctx, sessionID)
	if err != nil {
		_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
		return Result{Indexed: true, Source: "guac", Skipped: "no_recording"}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	lines, tim, mouse, err := guacindex.ParseKeysMouseAndTiming(f)
	if err != nil {
		return Result{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	dlp := contentDLP(row)
	var piiTotal outputPIIStats
	piiTotal.kinds = map[string]struct{}{}
	for _, ln := range lines {
		text, skip, st := applyContentDLP(dlp, ln.Text)
		if skip {
			mergePIIStats(&piiTotal, st)
			continue
		}
		if st != nil {
			mergePIIStats(&piiTotal, st)
		}
		ts := base.Add(time.Duration(ln.Offset * float64(time.Second)))
		payload := map[string]any{"line": text, "source": "guac", "offset": ln.Offset}
		if err := s.sess.AddEventAt(ctx, sessionID, ts, "keystroke", payload); err != nil {
			return Result{}, err
		}
	}
	if ev := dlpPayload(&piiTotal, "keystroke"); ev != nil {
		_ = s.sess.AddEventAt(ctx, sessionID, base, "dlp", ev)
	}
	s.evaluateKeystrokeUEBA(ctx, row, tim)
	s.evaluateMouseUEBA(ctx, row, mouse)
	_ = s.sess.MarkTranscriptIndexed(ctx, sessionID)
	n, _ = s.sess.CountKeystrokes(ctx, sessionID)
	return Result{Indexed: true, Source: "guac", Keystrokes: n}, nil
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
