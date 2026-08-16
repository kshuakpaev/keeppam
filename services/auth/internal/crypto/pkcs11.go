package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const pkcs11TokenType = "keeppam-pkcs11-token"

// PKCS11Provider unwraps the 32-byte DEK using a PIN-locked KEK.
//
// Two backends (no CGO, no SPIRE-style extra daemon in compose):
//   - token file: KEK wrapped by scrypt(PIN), DEK wrapped by KEK (AES-GCM)
//   - helper: exec a PKCS#11 unwrap helper that talks to a real module (SoftHSM/Thales)
type PKCS11Provider struct {
	TokenFile  string
	Module     string
	Helper     string
	Label      string
	TokenLabel string
	PIN        string
	Ciphertext string
}

func (p PKCS11Provider) Source() string { return "pkcs11" }

func (p PKCS11Provider) Load(ctx context.Context) ([]byte, error) {
	if p.Helper != "" {
		return unwrapPKCS11Helper(ctx, p)
	}
	if p.TokenFile == "" {
		if p.Module != "" {
			return nil, fmt.Errorf("pkcs11: module %q requires KEEPPAM_PKCS11_HELPER (CGO-free binary does not dlopen PKCS#11); or use KEEPPAM_PKCS11_TOKEN_FILE", p.Module)
		}
		return nil, fmt.Errorf("KEEPPAM_PKCS11_TOKEN_FILE or KEEPPAM_PKCS11_HELPER required when SOURCE=pkcs11")
	}
	if strings.TrimSpace(p.PIN) == "" {
		return nil, fmt.Errorf("KEEPPAM_PKCS11_PIN or KEEPPAM_PKCS11_PIN_FILE required")
	}
	ct := strings.TrimSpace(p.Ciphertext)
	if ct == "" {
		return nil, fmt.Errorf("KEEPPAM_KMS_CIPHERTEXT required when SOURCE=pkcs11")
	}
	wrappedDEK, err := decodeB64(ct)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 ciphertext: %w", err)
	}
	kek, err := UnlockPKCS11Token(p.TokenFile, p.PIN)
	if err != nil {
		return nil, err
	}
	env, err := NewEnvelope(kek)
	if err != nil {
		return nil, err
	}
	dek, err := env.Decrypt(wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: unwrap DEK failed")
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("pkcs11: DEK must be 32 bytes")
	}
	return dek, nil
}

type pkcs11TokenJSON struct {
	Version    int    `json:"version"`
	Type       string `json:"type"`
	Label      string `json:"label"`
	KeyLabel   string `json:"key_label"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	WrappedKEK string `json:"wrapped_kek"`
}

// InitPKCS11Token writes a PIN-locked software token containing kek (32 bytes).
func InitPKCS11Token(path, pin, label, keyLabel string, kek []byte) error {
	if len(kek) != 32 {
		return fmt.Errorf("pkcs11: KEK must be 32 bytes")
	}
	if strings.TrimSpace(pin) == "" {
		return fmt.Errorf("pkcs11: PIN required")
	}
	if label == "" {
		label = "KeepPAM"
	}
	if keyLabel == "" {
		keyLabel = "keeppam-kek"
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	n, r, p := 1<<15, 8, 1
	derived, err := scrypt.Key([]byte(pin), salt, n, r, p, 32)
	if err != nil {
		return err
	}
	env, err := NewEnvelope(derived)
	if err != nil {
		return err
	}
	wrapped, err := env.Encrypt(kek)
	if err != nil {
		return err
	}
	doc := pkcs11TokenJSON{
		Version: 1, Type: pkcs11TokenType, Label: label, KeyLabel: keyLabel,
		KDF: "scrypt", N: n, R: r, P: p,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		WrappedKEK: base64.StdEncoding.EncodeToString(wrapped),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, raw, 0o600)
}

func UnlockPKCS11Token(path, pin string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 token: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("pkcs11 token %s must be mode 0600 (got %o)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc pkcs11TokenJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("pkcs11 token: %w", err)
	}
	if doc.Type != pkcs11TokenType || doc.Version != 1 {
		return nil, fmt.Errorf("pkcs11 token: unsupported type/version")
	}
	if strings.ToLower(doc.KDF) != "scrypt" {
		return nil, fmt.Errorf("pkcs11 token: unsupported kdf")
	}
	salt, err := decodeB64(doc.Salt)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 token salt: %w", err)
	}
	wrapped, err := decodeB64(doc.WrappedKEK)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 token kek: %w", err)
	}
	n, r, p := doc.N, doc.R, doc.P
	if n <= 0 {
		n = 1 << 15
	}
	if r <= 0 {
		r = 8
	}
	if p <= 0 {
		p = 1
	}
	derived, err := scrypt.Key([]byte(pin), salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	env, err := NewEnvelope(derived)
	if err != nil {
		return nil, err
	}
	kek, err := env.Decrypt(wrapped)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: login failed")
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("pkcs11: KEK must be 32 bytes")
	}
	return kek, nil
}

// WrapDEKWithKEK AES-GCM-wraps a 32-byte DEK (same format as KEEPPAM_KMS_CIPHERTEXT).
func WrapDEKWithKEK(kek, dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("pkcs11: DEK must be 32 bytes")
	}
	env, err := NewEnvelope(kek)
	if err != nil {
		return nil, err
	}
	return env.Encrypt(dek)
}

func unwrapPKCS11Helper(ctx context.Context, p PKCS11Provider) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Helper)
	cmd.Env = os.Environ()
	if p.PIN != "" {
		cmd.Env = append(cmd.Env, "KEEPPAM_PKCS11_PIN="+p.PIN)
	}
	if p.Module != "" {
		cmd.Env = append(cmd.Env, "KEEPPAM_PKCS11_MODULE="+p.Module)
	}
	if p.Label != "" {
		cmd.Env = append(cmd.Env, "KEEPPAM_PKCS11_LABEL="+p.Label)
	}
	if p.TokenLabel != "" {
		cmd.Env = append(cmd.Env, "KEEPPAM_PKCS11_TOKEN="+p.TokenLabel)
	}
	if p.Ciphertext != "" {
		cmd.Env = append(cmd.Env, "KEEPPAM_KMS_CIPHERTEXT="+p.Ciphertext)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("pkcs11 helper: %s", truncate(msg, 200))
	}
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 32 {
		return append([]byte(nil), out...), nil
	}
	return decodeDEK(string(out))
}

type PKCS11URI struct {
	TokenLabel string
	KeyLabel   string
	Module     string
	PIN        string
	PINSource  string
	SlotID     int
}

func ParsePKCS11URI(raw string) (PKCS11URI, error) {
	var out PKCS11URI
	s := strings.TrimSpace(raw)
	if s == "" {
		return out, fmt.Errorf("empty pkcs11 uri")
	}
	if !strings.HasPrefix(strings.ToLower(s), "pkcs11:") {
		return out, fmt.Errorf("pkcs11 uri must start with pkcs11:")
	}
	rest := s[len("pkcs11:"):]
	path, query, _ := strings.Cut(rest, "?")
	for _, part := range strings.Split(path, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v, _ = url.QueryUnescape(v)
		switch strings.ToLower(k) {
		case "token":
			out.TokenLabel = v
		case "object", "id":
			if out.KeyLabel == "" || strings.ToLower(k) == "object" {
				out.KeyLabel = v
			}
		}
	}
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return out, fmt.Errorf("pkcs11 uri query: %w", err)
		}
		if v := q.Get("module-path"); v != "" {
			out.Module = v
		} else if v := q.Get("module-name"); v != "" {
			out.Module = v
		}
		if v := q.Get("pin-value"); v != "" {
			out.PIN = v
		}
		if v := q.Get("pin-source"); v != "" {
			out.PINSource = strings.TrimPrefix(v, "file:")
		}
		if v := q.Get("slot-id"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return out, fmt.Errorf("pkcs11 uri slot-id")
			}
			out.SlotID = n
		}
	}
	return out, nil
}

func NewPKCS11FromEnv() (KeyProvider, error) {
	p := PKCS11Provider{
		TokenFile:  os.Getenv("KEEPPAM_PKCS11_TOKEN_FILE"),
		Module:     os.Getenv("KEEPPAM_PKCS11_MODULE"),
		Helper:     os.Getenv("KEEPPAM_PKCS11_HELPER"),
		Label:      firstEnv("KEEPPAM_PKCS11_LABEL", "KEEPPAM_PKCS11_OBJECT"),
		TokenLabel: os.Getenv("KEEPPAM_PKCS11_TOKEN"),
		PIN:        "",
		Ciphertext: firstEnv("KEEPPAM_KMS_CIPHERTEXT", "KEEPPAM_VAULT_CIPHERTEXT"),
	}
	pin, err := pkcs11PINFromEnv()
	if err != nil {
		return nil, err
	}
	p.PIN = pin
	if uri := strings.TrimSpace(os.Getenv("KEEPPAM_PKCS11_URI")); uri != "" {
		u, err := ParsePKCS11URI(uri)
		if err != nil {
			return nil, err
		}
		if p.TokenLabel == "" {
			p.TokenLabel = u.TokenLabel
		}
		if p.Label == "" {
			p.Label = u.KeyLabel
		}
		if p.Module == "" {
			p.Module = u.Module
		}
		if p.PIN == "" && u.PIN != "" {
			p.PIN = u.PIN
		}
		if p.PIN == "" && u.PINSource != "" {
			b, err := os.ReadFile(u.PINSource)
			if err != nil {
				return nil, fmt.Errorf("pkcs11 pin-source: %w", err)
			}
			p.PIN = strings.TrimSpace(string(b))
		}
	}
	if p.TokenFile == "" && p.Helper == "" && p.Module == "" {
		return nil, fmt.Errorf("KEEPPAM_PKCS11_TOKEN_FILE, KEEPPAM_PKCS11_HELPER or KEEPPAM_PKCS11_MODULE required when SOURCE=pkcs11")
	}
	return p, nil
}

func pkcs11PINFromEnv() (string, error) {
	if v := strings.TrimSpace(os.Getenv("KEEPPAM_PKCS11_PIN")); v != "" {
		return v, nil
	}
	path := strings.TrimSpace(os.Getenv("KEEPPAM_PKCS11_PIN_FILE"))
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("KEEPPAM_PKCS11_PIN_FILE: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	var last error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, last
}
