package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/license"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db         *store.DB
	aud        *audit.Service
	sess       *sessionsvc.Service
	policy     *policy.Service
	allowExt   bool
	licensed   func() bool
}

func New(db *store.DB, aud *audit.Service, sess *sessionsvc.Service, pol *policy.Service) *Service {
	s := &Service{db: db, aud: aud, sess: sess, policy: pol}
	s.allowExt = strings.TrimSpace(os.Getenv("KEEPPAM_AI_ALLOW_EXTERNAL")) == "1"
	s.licensed = func() bool { return true }
	return s
}

func (s *Service) SetLicense(fn func() bool) {
	if fn != nil {
		s.licensed = fn
	}
}

func (s *Service) Licensed() bool {
	if s == nil || s.licensed == nil {
		return true
	}
	return s.licensed()
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	var out Settings
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(mode,'off'), COALESCE(endpoint,''), COALESCE(model,''), COALESCE(embed_model,''),
		       COALESCE(max_input_chars,48000), COALESCE(timeout_s,90), COALESCE(lang,'ru'),
		       last_run_at, COALESCE(last_error,''), updated_at
		FROM ai_settings WHERE id=1`).Scan(
		&out.Mode, &out.Endpoint, &out.Model, &out.EmbedModel, &out.MaxInputChars, &out.TimeoutS, &out.Lang,
		&out.LastRunAt, &out.LastError, &out.UpdatedAt,
	)
	if err != nil {
		return Settings{}, err
	}
	out.AllowExternal = s.allowExt
	out.Licensed = s.Licensed()
	return out, nil
}

func (s *Service) Put(ctx context.Context, actor uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	switch mode {
	case ModeOff, ModeOn:
	case ModeExternal:
		if !s.allowExt {
			return Settings{}, fmt.Errorf("external AI disabled (KEEPPAM_AI_ALLOW_EXTERNAL)")
		}
	default:
		return Settings{}, fmt.Errorf("mode must be off, on, or external")
	}
	ep := strings.TrimSpace(in.Endpoint)
	if ep == "" {
		ep = "mock://local"
	}
	if mode == ModeExternal && (strings.HasPrefix(ep, "mock://") || ep == "mock") {
		return Settings{}, fmt.Errorf("external mode needs http(s) endpoint")
	}
	model := strings.TrimSpace(in.Model)
	if model == "" {
		model = "mock"
	}
	embed := strings.TrimSpace(in.EmbedModel)
	if embed == "" {
		embed = model
	}
	maxc := in.MaxInputChars
	if maxc < 4000 {
		maxc = 48000
	}
	if maxc > 200000 {
		maxc = 200000
	}
	to := in.TimeoutS
	if to < 15 {
		to = 90
	}
	if to > 300 {
		to = 300
	}
	lang := strings.ToLower(strings.TrimSpace(in.Lang))
	switch lang {
	case "ru", "en", "session":
	default:
		lang = "ru"
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ai_settings (id, mode, endpoint, model, embed_model, max_input_chars, timeout_s, lang, updated_at)
		VALUES (1, $1,$2,$3,$4,$5,$6,$7, NOW())
		ON CONFLICT (id) DO UPDATE SET
			mode=EXCLUDED.mode, endpoint=EXCLUDED.endpoint, model=EXCLUDED.model,
			embed_model=EXCLUDED.embed_model, max_input_chars=EXCLUDED.max_input_chars,
			timeout_s=EXCLUDED.timeout_s, lang=EXCLUDED.lang, updated_at=NOW()`,
		mode, ep, model, embed, maxc, to, lang)
	if err != nil {
		return Settings{}, err
	}
	if s.aud != nil {
		_ = s.aud.Record(ctx, &actor, "ai.settings.updated", "ai", "1", ip, ua, map[string]any{
			"mode": mode, "model": model, "endpoint_kind": endpointKind(ep),
		})
		if mode == ModeExternal {
			_ = s.aud.Record(ctx, &actor, "ai.external.used", "ai", "1", ip, ua, map[string]any{"via": "settings"})
		}
	}
	return s.Get(ctx)
}

func endpointKind(ep string) string {
	if isMockEndpoint(ep) {
		return "mock"
	}
	if strings.HasPrefix(strings.ToLower(ep), "https://") {
		return "https"
	}
	if strings.HasPrefix(strings.ToLower(ep), "http://") {
		return "http"
	}
	return "other"
}

func (s *Service) Enabled(ctx context.Context) bool {
	cfg, err := s.Get(ctx)
	return err == nil && cfg.Mode != ModeOff
}

func (s *Service) runtimeFor(cfg Settings) runtimeClient {
	if isMockEndpoint(cfg.Endpoint) || cfg.Model == "mock" {
		return mockRuntime{}
	}
	return newHTTPRuntime(time.Duration(cfg.TimeoutS) * time.Second)
}

func (s *Service) Test(ctx context.Context) (map[string]any, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Mode == ModeOff {
		return map[string]any{"ok": true, "mode": cfg.Mode, "skipped": true, "model": cfg.Model}, nil
	}
	rt := s.runtimeFor(cfg)
	if err := rt.Probe(ctx, cfg); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "mode": cfg.Mode, "model": cfg.Model, "endpoint_kind": endpointKind(cfg.Endpoint)}, nil
}

func (s *Service) recordRun(ctx context.Context, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE ai_settings SET last_run_at=NOW(), last_error=$1, updated_at=NOW() WHERE id=1`, msg)
}

func (s *Service) langOf(cfg Settings) string {
	if cfg.Lang == "en" {
		return "en"
	}
	return "ru"
}

// LicenseOK is used by HTTP: unlicensed/dev and ai_copilot flag.
func LicenseOK(f license.File) bool {
	return f.AllowAICopilot()
}
