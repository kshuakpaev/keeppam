package eidas

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/pades"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	Mode           string     `json:"mode"`
	Profile        string     `json:"profile"`
	RequireBLTA    bool       `json:"require_b_lta"`
	PKCS11Enabled  bool       `json:"pkcs11_enabled"`
	PKCS11Module   string     `json:"pkcs11_module,omitempty"`
	PKCS11Label    string     `json:"pkcs11_label,omitempty"`
	PKCS11Pin      string     `json:"pkcs11_pin,omitempty"`
	HasPKCS11Pin   bool       `json:"has_pkcs11_pin"`
	LastCheckAt    *time.Time `json:"last_check_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	CertCN         string     `json:"cert_cn,omitempty"`
	CertQualified  bool       `json:"cert_qualified"`
	PadesProfile   string     `json:"pades_profile,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

type TestResult struct {
	Mode          string `json:"mode"`
	Profile       string `json:"profile"`
	CertCN        string `json:"cert_cn"`
	CertQualified bool   `json:"cert_qualified"`
	PadesProfile  string `json:"pades_profile"`
	PKCS11        bool   `json:"pkcs11"`
	Detail        string `json:"detail,omitempty"`
	Ready         bool   `json:"ready"`
}

type Service struct {
	db   *store.DB
	aud  *audit.Service
	env  *crypto.Envelope
	cfg  config.Config
	base *pades.Signer
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope, cfg config.Config, base *pades.Signer) *Service {
	return &Service{db: db, aud: aud, env: env, cfg: cfg, base: base}
}

func (s *Service) SetBaseSigner(sig *pades.Signer) {
	if s != nil {
		s.base = sig
	}
}

func NormalizeMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "off", nil
	case "advanced":
		return "advanced", nil
	case "qualified":
		return "qualified", nil
	default:
		return "", fmt.Errorf("eidas mode must be off, advanced, or qualified")
	}
}

func NormalizeProfile(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "eidas", "eu":
		return "eidas", nil
	case "fstec", "ru", "gost":
		return "fstec", nil
	default:
		return "", fmt.Errorf("eidas profile must be eidas or fstec")
	}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	cfg, err := s.load(ctx)
	if err != nil {
		return Settings{}, err
	}
	if s.base != nil {
		if sig, err := s.BuildSigner(ctx); err == nil && sig != nil {
			cfg.PadesProfile = sig.Profile()
			if sig.Cert != nil {
				cfg.CertCN = sig.CN()
				ok, _ := pades.CertQualified(sig.Cert, cfg.Profile)
				cfg.CertQualified = ok
			}
		}
	}
	return cfg, nil
}

func (s *Service) load(ctx context.Context) (Settings, error) {
	var out Settings
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(mode,'off'), COALESCE(profile,'eidas'), COALESCE(require_b_lta,TRUE),
			COALESCE(pkcs11_enabled,FALSE), COALESCE(pkcs11_module,''), COALESCE(pkcs11_label,''),
			(octet_length(pkcs11_pin_enc) > 0), last_check_at, COALESCE(last_error,''),
			COALESCE(cert_cn,''), COALESCE(cert_qualified,FALSE), updated_at
		FROM eidas_settings WHERE id=1`).Scan(
		&out.Mode, &out.Profile, &out.RequireBLTA, &out.PKCS11Enabled,
		&out.PKCS11Module, &out.PKCS11Label, &out.HasPKCS11Pin,
		&out.LastCheckAt, &out.LastError, &out.CertCN, &out.CertQualified, &updatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Settings{Mode: "off", Profile: "eidas", RequireBLTA: true}, nil
		}
		return Settings{}, err
	}
	out.UpdatedAt = &updatedAt
	return out, nil
}

func (s *Service) loadPin(ctx context.Context) (Settings, string, error) {
	cfg, err := s.load(ctx)
	if err != nil {
		return Settings{}, "", err
	}
	enc, err := s.loadPinEnc(ctx)
	if err != nil {
		return Settings{}, "", err
	}
	pin := ""
	if len(enc) > 0 && s.env != nil {
		if b, err := s.env.Decrypt(enc); err == nil {
			pin = string(b)
		}
	}
	return cfg, pin, nil
}

func (s *Service) loadPinEnc(ctx context.Context) ([]byte, error) {
	var enc []byte
	err := s.db.Pool.QueryRow(ctx, `SELECT pkcs11_pin_enc FROM eidas_settings WHERE id=1`).Scan(&enc)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	return enc, nil
}

func (s *Service) Put(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	mode, err := NormalizeMode(in.Mode)
	if err != nil {
		return Settings{}, err
	}
	profile, err := NormalizeProfile(in.Profile)
	if err != nil {
		return Settings{}, err
	}
	requireBLTA := in.RequireBLTA
	if mode == "qualified" && !in.RequireBLTA {
		requireBLTA = true
	}
	pinEnc, err := s.loadPinEnc(ctx)
	if err != nil {
		return Settings{}, err
	}
	if in.PKCS11Enabled {
		if strings.TrimSpace(in.PKCS11Module) == "" || strings.TrimSpace(in.PKCS11Label) == "" {
			return Settings{}, fmt.Errorf("pkcs11_module and pkcs11_label required when pkcs11_enabled")
		}
	}
	if strings.TrimSpace(in.PKCS11Pin) != "" {
		if s.env == nil {
			return Settings{}, fmt.Errorf("encryption unavailable")
		}
		pinEnc, err = s.env.Encrypt([]byte(strings.TrimSpace(in.PKCS11Pin)))
		if err != nil {
			return Settings{}, err
		}
	}
	if in.PKCS11Enabled && len(pinEnc) == 0 && strings.TrimSpace(s.cfg.PDFPKCS11Helper) == "" {
		return Settings{}, fmt.Errorf("pkcs11 pin or KEEPPAM_PDF_PKCS11_HELPER required")
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO eidas_settings (id, mode, profile, require_b_lta, pkcs11_enabled,
			pkcs11_module, pkcs11_label, pkcs11_pin_enc, updated_at)
		VALUES (1,$1,$2,$3,$4,$5,$6,$7,NOW())
		ON CONFLICT (id) DO UPDATE SET
			mode=EXCLUDED.mode, profile=EXCLUDED.profile, require_b_lta=EXCLUDED.require_b_lta,
			pkcs11_enabled=EXCLUDED.pkcs11_enabled, pkcs11_module=EXCLUDED.pkcs11_module,
			pkcs11_label=EXCLUDED.pkcs11_label,
			pkcs11_pin_enc=COALESCE(EXCLUDED.pkcs11_pin_enc, eidas_settings.pkcs11_pin_enc),
			updated_at=NOW()`,
		mode, profile, requireBLTA, in.PKCS11Enabled,
		strings.TrimSpace(in.PKCS11Module), strings.TrimSpace(in.PKCS11Label), pinEnc)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "eidas.settings.updated", "eidas", "1", ip, ua, map[string]any{
		"mode": mode, "profile": profile, "pkcs11": in.PKCS11Enabled,
	})
	res, _ := s.Test(ctx)
	s.recordCheck(ctx, res.Ready, res.CertCN, res.CertQualified, res.Detail)
	return s.Get(ctx)
}

func (s *Service) Test(ctx context.Context) (TestResult, error) {
	cfg, err := s.load(ctx)
	if err != nil {
		return TestResult{}, err
	}
	out := TestResult{Mode: cfg.Mode, Profile: cfg.Profile}
	if cfg.Mode == "off" {
		out.Detail = "eidas mode off"
		out.Ready = true
		return out, nil
	}
	if s.base == nil {
		out.Detail = "PDF signer not configured"
		return out, fmt.Errorf("KEEPPAM_PDF_CERT_FILE not set")
	}
	sig, err := s.BuildSigner(ctx)
	if err != nil {
		out.Detail = err.Error()
		return out, err
	}
	if sig == nil {
		out.Detail = "PDF signer not configured"
		return out, fmt.Errorf("KEEPPAM_PDF_CERT_FILE not set")
	}
	out.PadesProfile = sig.Profile()
	out.PKCS11 = sig.PKCS11
	if sig.Cert != nil {
		out.CertCN = sig.CN()
		ok, detail := pades.CertQualified(sig.Cert, cfg.Profile)
		out.CertQualified = ok
		out.Detail = detail
	}
	switch cfg.Mode {
	case "qualified":
		if err := pades.ValidateQualifiedExport(sig, cfg.Profile, cfg.RequireBLTA); err != nil {
			out.Detail = err.Error()
			return out, nil
		}
		if cfg.PKCS11Enabled && !sig.PKCS11 {
			out.Detail = "qualified mode with pkcs11_enabled requires HSM/PKCS#11 PDF key"
			return out, nil
		}
		out.Ready = out.CertQualified
	case "advanced":
		if cfg.RequireBLTA && !sig.LTAEnabled() {
			out.Detail = "advanced mode requires PAdES-B-LTA"
			return out, nil
		}
		out.Ready = true
		out.Detail = "advanced PAdES " + sig.Profile()
	default:
		out.Ready = true
	}
	return out, nil
}

func (s *Service) recordCheck(ctx context.Context, ok bool, cn string, qualified bool, detail string) {
	msg := detail
	if !ok && msg == "" {
		msg = "not ready"
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE eidas_settings SET last_check_at=NOW(), last_error=$1,
			cert_cn=$2, cert_qualified=$3, updated_at=NOW()
		WHERE id=1`, msg, cn, qualified)
}

// BuildSigner returns base or PKCS#11 overlay from DB settings.
func (s *Service) BuildSigner(ctx context.Context) (*pades.Signer, error) {
	if s == nil || s.base == nil {
		return nil, nil
	}
	cfg, pin, err := s.loadPin(ctx)
	if err != nil {
		return nil, err
	}
	sig := s.base.Clone()
	if !cfg.PKCS11Enabled {
		return sig, nil
	}
	helper := strings.TrimSpace(s.cfg.PDFPKCS11Helper)
	if helper == "" {
		return nil, fmt.Errorf("KEEPPAM_PDF_PKCS11_HELPER required for pkcs11_enabled")
	}
	module := strings.TrimSpace(cfg.PKCS11Module)
	if module == "" {
		module = strings.TrimSpace(s.cfg.PDFPKCS11Module)
	}
	label := strings.TrimSpace(cfg.PKCS11Label)
	if label == "" {
		return nil, fmt.Errorf("pkcs11_label required")
	}
	hsm, err := pades.LoadCertOnly(s.cfg.PDFCertFile)
	if err != nil {
		return nil, err
	}
	hsm.TSAURL = sig.TSAURL
	hsm.LTV = sig.LTV
	hsm.LTVDir = sig.LTVDir
	hsm.LTVFetch = sig.LTVFetch
	hsm.LTA = sig.LTA
	if err := pades.AttachPKCS11Helper(hsm, helper, module, label, pin); err != nil {
		return nil, err
	}
	return hsm, nil
}

// ApplySigner annotates PAdES signer from DB policy (qualified label, export gate).
func (s *Service) ApplySigner(ctx context.Context, sig *pades.Signer) error {
	if s == nil || sig == nil || s.db == nil {
		return nil
	}
	cfg, err := s.load(ctx)
	if err != nil || cfg.Mode == "off" {
		return nil
	}
	ok, _ := pades.CertQualified(sig.Cert, cfg.Profile)
	sig.RegProfile = cfg.Profile
	sig.Qualified = cfg.Mode == "qualified" && ok
	if cfg.Mode == "qualified" {
		return pades.ValidateQualifiedExport(sig, cfg.Profile, cfg.RequireBLTA)
	}
	if cfg.Mode == "advanced" && cfg.RequireBLTA && !sig.LTAEnabled() {
		return fmt.Errorf("eidas advanced mode requires PAdES-B-LTA")
	}
	return nil
}

// StatusFields for compliance page.
func (s *Service) StatusFields(ctx context.Context) (mode, profile string, qualified bool) {
	cfg, err := s.load(ctx)
	if err != nil || cfg.Mode == "off" {
		return "off", "", false
	}
	return cfg.Mode, cfg.Profile, cfg.CertQualified && cfg.Mode == "qualified"
}
