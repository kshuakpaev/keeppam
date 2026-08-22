package nac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	Mode        string     `json:"mode"`
	APIURL      string     `json:"api_url"`
	APIToken    string     `json:"api_token,omitempty"`
	HasAPIToken bool       `json:"has_api_token"`
	Vendor      string     `json:"vendor"`
	TimeoutMS   int        `json:"timeout_ms"`
	LastCheckAt *time.Time `json:"last_check_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

type Service struct {
	db   *store.DB
	aud  *audit.Service
	env  *crypto.Envelope
	sess *sessionsvc.Service
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope, sess *sessionsvc.Service) *Service {
	return &Service{db: db, aud: aud, env: env, sess: sess}
}

func NormalizeMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "off", nil
	case "audit":
		return "audit", nil
	case "enforce":
		return "enforce", nil
	default:
		return "", fmt.Errorf("nac mode must be off, audit, or enforce")
	}
}

func NormalizeVendor(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "generic":
		return "generic", nil
	case "cisco_ise":
		return "cisco_ise", nil
	default:
		return "", fmt.Errorf("nac vendor must be generic or cisco_ise")
	}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	cfg, _, err := s.load(ctx)
	return cfg, err
}

func (s *Service) load(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var tokEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(mode,'off'), COALESCE(api_url,''), api_token_enc,
			COALESCE(vendor,'generic'), COALESCE(timeout_ms,3000),
			last_check_at, COALESCE(last_error,''), updated_at
		FROM nac_settings WHERE id=1`).Scan(
		&out.Mode, &out.APIURL, &tokEnc, &out.Vendor, &out.TimeoutMS,
		&out.LastCheckAt, &out.LastError, &updatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Settings{Mode: "off", Vendor: "generic", TimeoutMS: 3000}, nil, nil
		}
		return Settings{}, nil, err
	}
	if out.TimeoutMS < 500 {
		out.TimeoutMS = 3000
	}
	out.HasAPIToken = len(tokEnc) > 0
	out.UpdatedAt = &updatedAt
	return out, tokEnc, nil
}

func (s *Service) loadToken(ctx context.Context) (Settings, string, error) {
	cfg, enc, err := s.load(ctx)
	if err != nil {
		return Settings{}, "", err
	}
	tok := ""
	if len(enc) > 0 && s.env != nil {
		if b, err := s.env.Decrypt(enc); err == nil {
			tok = string(b)
		}
	}
	return cfg, tok, nil
}

func (s *Service) Put(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	mode, err := NormalizeMode(in.Mode)
	if err != nil {
		return Settings{}, err
	}
	vendor, err := NormalizeVendor(in.Vendor)
	if err != nil {
		return Settings{}, err
	}
	apiURL := strings.TrimSpace(in.APIURL)
	if mode != "off" && apiURL == "" {
		return Settings{}, fmt.Errorf("api_url required when mode is not off")
	}
	timeout := in.TimeoutMS
	if timeout <= 0 {
		timeout = 3000
	}
	if timeout < 500 || timeout > 30000 {
		return Settings{}, fmt.Errorf("timeout_ms must be 500..30000")
	}
	_, tokEnc, err := s.load(ctx)
	if err != nil {
		return Settings{}, err
	}
	if strings.TrimSpace(in.APIToken) != "" {
		if s.env == nil {
			return Settings{}, fmt.Errorf("encryption unavailable")
		}
		tokEnc, err = s.env.Encrypt([]byte(strings.TrimSpace(in.APIToken)))
		if err != nil {
			return Settings{}, err
		}
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO nac_settings (id, mode, api_url, api_token_enc, vendor, timeout_ms, updated_at)
		VALUES (1,$1,$2,$3,$4,$5,NOW())
		ON CONFLICT (id) DO UPDATE SET
			mode=EXCLUDED.mode, api_url=EXCLUDED.api_url,
			api_token_enc=EXCLUDED.api_token_enc,
			vendor=EXCLUDED.vendor, timeout_ms=EXCLUDED.timeout_ms, updated_at=NOW()`,
		mode, apiURL, tokEnc, vendor, timeout)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "nac.settings.updated", "nac", "1", ip, ua, map[string]any{
		"mode": mode, "vendor": vendor,
	})
	return s.Get(ctx)
}

func (s *Service) assetName(ctx context.Context, id uuid.UUID) string {
	var name string
	_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM assets WHERE id=$1`, id).Scan(&name)
	return name
}

func (s *Service) Test(ctx context.Context) (PostureResponse, error) {
	cfg, tok, err := s.loadToken(ctx)
	if err != nil {
		return PostureResponse{}, err
	}
	if cfg.Mode == "off" || cfg.APIURL == "" {
		return PostureResponse{}, fmt.Errorf("nac disabled or api_url empty")
	}
	req := PostureRequest{
		Event: "test", ClientIP: "127.0.0.1", Devices: []string{"TLS"},
		UserID: uuid.Nil.String(), Username: "keeppam-test", AssetID: uuid.Nil.String(),
		AssetName: "test", Protocol: "ssh",
	}
	resp, err := callPosture(ctx, cfg.APIURL, tok, cfg.Vendor, time.Duration(cfg.TimeoutMS)*time.Millisecond, req)
	s.recordCheck(ctx, err)
	return resp, err
}

func (s *Service) recordCheck(ctx context.Context, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE nac_settings SET last_check_at=NOW(), last_error=$1, updated_at=NOW() WHERE id=1`, msg)
}

type ConnectInput struct {
	UserID      uuid.UUID
	Username    string
	AssetID     uuid.UUID
	AssetName   string
	Protocol    string
	ClientIP    string
	ClientMAC   string
	ClientDevices []string
}

// CheckPreConnect runs posture before session create. Returns deny=true only in enforce mode.
func (s *Service) CheckPreConnect(ctx context.Context, in ConnectInput) (resp PostureResponse, auditOnly bool, deny bool, err error) {
	cfg, tok, err := s.loadToken(ctx)
	if err != nil {
		return PostureResponse{}, false, false, err
	}
	if cfg.Mode == "off" || cfg.APIURL == "" {
		return PostureResponse{Allowed: true}, false, false, nil
	}
	req := PostureRequest{
		Event: "pre_connect", ClientIP: strings.TrimSpace(in.ClientIP),
		ClientMAC: strings.TrimSpace(in.ClientMAC), Devices: in.ClientDevices,
		UserID: in.UserID.String(), Username: in.Username,
		AssetID: in.AssetID.String(), AssetName: in.AssetName, Protocol: in.Protocol,
	}
	resp, err = callPosture(ctx, cfg.APIURL, tok, cfg.Vendor, time.Duration(cfg.TimeoutMS)*time.Millisecond, req)
	s.recordCheck(ctx, err)
	if err != nil {
		if cfg.Mode == "enforce" {
			return PostureResponse{}, false, true, nil
		}
		return PostureResponse{}, true, false, nil
	}
	if resp.Allowed {
		return resp, false, false, nil
	}
	if cfg.Mode == "enforce" {
		return resp, false, true, nil
	}
	return resp, true, false, nil
}

func (s *Service) OnSessionStart(ctx context.Context, sessionID uuid.UUID) {
	s.notify(ctx, sessionID, "session_start")
}

func (s *Service) OnSessionEnd(ctx context.Context, sessionID uuid.UUID) {
	s.notify(ctx, sessionID, "session_end")
}

func (s *Service) notify(ctx context.Context, sessionID uuid.UUID, event string) {
	if s == nil || s.sess == nil {
		return
	}
	cfg, tok, err := s.loadToken(ctx)
	if err != nil || cfg.Mode == "off" || cfg.APIURL == "" {
		return
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return
	}
	assetName := s.assetName(ctx, row.AssetID)
	req := PostureRequest{
		Event: event, ClientIP: row.ClientIP, UserID: row.UserID.String(),
		AssetID: row.AssetID.String(), AssetName: assetName, Protocol: row.Protocol,
		SessionID: sessionID.String(),
	}
	resp, err := callPosture(ctx, cfg.APIURL, tok, cfg.Vendor, time.Duration(cfg.TimeoutMS)*time.Millisecond, req)
	s.recordCheck(ctx, err)
	payload := map[string]any{"event": event, "session_id": sessionID.String()}
	if err != nil {
		payload["error"] = err.Error()
	} else {
		payload["allowed"] = resp.Allowed
		if resp.VLAN != "" {
			payload["vlan"] = resp.VLAN
		}
		if resp.Policy != "" {
			payload["policy"] = resp.Policy
		}
		if resp.Reason != "" {
			payload["reason"] = resp.Reason
		}
	}
	_ = s.sess.AddEvent(ctx, sessionID, "nac", payload)
	if s.aud != nil {
		_ = s.aud.Record(ctx, &row.UserID, "session.nac."+event, "session", sessionID.String(), row.ClientIP, "nac", payload)
	}
}
