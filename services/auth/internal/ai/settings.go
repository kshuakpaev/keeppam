package ai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/license"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db       *store.DB
	aud      *audit.Service
	sess     *sessionsvc.Service
	policy   *policy.Service
	env      *crypto.Envelope
	allowExt bool
	licensed func() bool
}

func New(db *store.DB, aud *audit.Service, sess *sessionsvc.Service, pol *policy.Service, env *crypto.Envelope) *Service {
	s := &Service{db: db, aud: aud, sess: sess, policy: pol, env: env}
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
	var keyEnc []byte
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(mode,'off'), COALESCE(endpoint,''), COALESCE(model,''), COALESCE(embed_model,''),
		       COALESCE(preset,''), api_key_enc,
		       COALESCE(max_input_chars,48000), COALESCE(timeout_s,90), COALESCE(lang,'ru'),
		       last_run_at, COALESCE(last_error,''), updated_at
		FROM ai_settings WHERE id=1`).Scan(
		&out.Mode, &out.Endpoint, &out.Model, &out.EmbedModel, &out.Preset, &keyEnc,
		&out.MaxInputChars, &out.TimeoutS, &out.Lang,
		&out.LastRunAt, &out.LastError, &out.UpdatedAt,
	)
	if err != nil {
		return Settings{}, err
	}
	out.HasAPIKey = len(keyEnc) > 0 || strings.TrimSpace(os.Getenv("KEEPPAM_AI_API_KEY")) != ""
	out.APIKey = ""
	out.runtimeKey = s.loadAPIKey(ctx)
	out.HasAPIKey = out.runtimeKey != ""
	out.AllowExternal = s.allowExt
	out.Licensed = s.Licensed()
	if strings.TrimSpace(out.Preset) == "" {
		out.Preset = MatchPreset(out.Endpoint, out.Model, out.EmbedModel, s.allowExt)
	}
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
	preset := strings.TrimSpace(in.Preset)
	if preset == "__custom__" {
		preset = ""
	}
	if p := FindPreset(preset); p != nil {
		if p.NeedsKey && !s.allowExt {
			return Settings{}, fmt.Errorf("external AI disabled (KEEPPAM_AI_ALLOW_EXTERNAL)")
		}
		if strings.TrimSpace(in.Model) == "" {
			in.Model = p.Model
		}
		if strings.TrimSpace(in.Endpoint) == "" {
			in.Endpoint = p.Endpoint
		}
		if strings.TrimSpace(in.EmbedModel) == "" {
			in.EmbedModel = p.EmbedModel
		}
		if p.Mode == ModeExternal {
			mode = ModeExternal
		}
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
	if preset == "" {
		preset = MatchPreset(ep, model, embed, s.allowExt)
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
	var keyEnc []byte
	_ = s.db.Pool.QueryRow(ctx, `SELECT api_key_enc FROM ai_settings WHERE id=1`).Scan(&keyEnc)
	keyIn := strings.TrimSpace(in.APIKey)
	switch {
	case keyIn == "-" || strings.EqualFold(keyIn, "clear"):
		keyEnc = nil
	case keyIn != "":
		if s.env == nil {
			return Settings{}, fmt.Errorf("api key storage unavailable")
		}
		enc, err := s.env.Encrypt([]byte(keyIn))
		if err != nil {
			return Settings{}, err
		}
		keyEnc = enc
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO ai_settings (id, mode, endpoint, model, embed_model, preset, api_key_enc, max_input_chars, timeout_s, lang, updated_at)
		VALUES (1, $1,$2,$3,$4,$5,$6,$7,$8,$9, NOW())
		ON CONFLICT (id) DO UPDATE SET
			mode=EXCLUDED.mode, endpoint=EXCLUDED.endpoint, model=EXCLUDED.model,
			embed_model=EXCLUDED.embed_model, preset=EXCLUDED.preset, api_key_enc=EXCLUDED.api_key_enc,
			max_input_chars=EXCLUDED.max_input_chars, timeout_s=EXCLUDED.timeout_s, lang=EXCLUDED.lang, updated_at=NOW()`,
		mode, ep, model, embed, preset, keyEnc, maxc, to, lang)
	if err != nil {
		return Settings{}, err
	}
	if s.aud != nil {
		_ = s.aud.Record(ctx, &actor, "ai.settings.updated", "ai", "1", ip, ua, map[string]any{
			"mode": mode, "model": model, "preset": preset, "endpoint_kind": endpointKind(ep),
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

func (s *Service) loadAPIKey(ctx context.Context) string {
	var enc []byte
	_ = s.db.Pool.QueryRow(ctx, `SELECT api_key_enc FROM ai_settings WHERE id=1`).Scan(&enc)
	if len(enc) > 0 && s.env != nil {
		if plain, err := s.env.Decrypt(enc); err == nil && len(plain) > 0 {
			return string(plain)
		}
	}
	return strings.TrimSpace(os.Getenv("KEEPPAM_AI_API_KEY"))
}

func (s *Service) ListModels(ctx context.Context) (ModelCatalog, error) {
	out := ModelCatalog{
		Presets: Catalog(s.allowExt),
		Runtime: []RuntimeModel{},
	}
	cfg, err := s.Get(ctx)
	if err != nil {
		return out, nil
	}
	out.Preset = cfg.Preset
	if isMockEndpoint(cfg.Endpoint) {
		return out, nil
	}
	rt := newHTTPRuntime(8 * time.Second)
	ids, lerr := rt.List(ctx, cfg)
	if lerr != nil {
		out.RuntimeError = lerr.Error()
		return out, nil
	}
	for _, id := range ids {
		out.Runtime = append(out.Runtime, RuntimeModel{ID: id, Source: "runtime", Installed: true})
	}
	return out, nil
}

func (s *Service) Pull(ctx context.Context, name string) (map[string]any, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = cfg.Model
	}
	if p := FindPreset(name); p != nil {
		name = p.Model
		if strings.TrimSpace(cfg.Endpoint) == "" || isMockEndpoint(cfg.Endpoint) {
			cfg.Endpoint = p.Endpoint
		}
	}
	if isMockEndpoint(cfg.Endpoint) {
		cfg.Endpoint = DefaultOllamaEndpoint
	}
	rt := newHTTPRuntime(10 * time.Minute)
	if err := rt.Pull(ctx, cfg, name); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "pulled": name, "endpoint": cfg.Endpoint}, nil
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
	return map[string]any{"ok": true, "mode": cfg.Mode, "model": cfg.Model, "preset": cfg.Preset, "endpoint_kind": endpointKind(cfg.Endpoint)}, nil
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
