package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// KeyProvider loads the 32-byte AES data key used by Envelope.
type KeyProvider interface {
	Load(ctx context.Context) ([]byte, error)
	Source() string
}

type EnvKeyProvider struct {
	RawB64 string
}

func (p EnvKeyProvider) Source() string { return "env" }

func (p EnvKeyProvider) Load(ctx context.Context) ([]byte, error) {
	_ = ctx
	if strings.TrimSpace(p.RawB64) == "" {
		return nil, fmt.Errorf("KEEPPAM_DATA_KEY empty")
	}
	key, err := base64.StdEncoding.DecodeString(p.RawB64)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("KEEPPAM_DATA_KEY must be base64-encoded 32 bytes")
	}
	return key, nil
}

type FileKeyProvider struct {
	Path string
}

func (p FileKeyProvider) Source() string { return "file" }

func (p FileKeyProvider) Load(ctx context.Context) ([]byte, error) {
	_ = ctx
	b, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(b))
	// accept raw 32 bytes or base64 text
	if len(b) == 32 && !strings.Contains(raw, "\n") && !isMostlyPrintable(b) {
		return b, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("key file %s must contain base64 of 32 bytes (or raw 32 bytes)", p.Path)
	}
	return key, nil
}

func isMostlyPrintable(b []byte) bool {
	n := 0
	for _, c := range b {
		if c >= 32 && c < 127 {
			n++
		}
	}
	return n > len(b)/2
}

// VaultTransitProvider calls Vault transit decrypt/export-style endpoint that returns base64 plaintext key.
// Expected response: {"data":{"plaintext":"<base64 32 bytes>"}}  (Vault transit decrypt shape).
type VaultTransitProvider struct {
	Addr  string
	Token string
	Path  string // e.g. /v1/transit/decrypt/keeppam
	Body  string // JSON body; default wraps ciphertext from env
}

func (p VaultTransitProvider) Source() string { return "vault" }

func (p VaultTransitProvider) Load(ctx context.Context) ([]byte, error) {
	addr := strings.TrimRight(p.Addr, "/")
	path := p.Path
	if path == "" {
		path = "/v1/transit/decrypt/keeppam"
	}
	body := p.Body
	if body == "" {
		ct := os.Getenv("KEEPPAM_VAULT_CIPHERTEXT")
		if ct == "" {
			return nil, fmt.Errorf("KEEPPAM_VAULT_CIPHERTEXT required for vault key source")
		}
		b, _ := json.Marshal(map[string]any{"ciphertext": ct})
		body = string(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {
		req.Header.Set("X-Vault-Token", p.Token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault dial: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("vault plaintext must be base64 of 32 bytes")
	}
	return key, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// NewKeyProviderFromEnv picks env|file|vault based on KEEPPAM_DATA_KEY_SOURCE.
func NewKeyProviderFromEnv() (KeyProvider, error) {
	src := strings.ToLower(strings.TrimSpace(os.Getenv("KEEPPAM_DATA_KEY_SOURCE")))
	switch src {
	case "", "env":
		return EnvKeyProvider{RawB64: os.Getenv("KEEPPAM_DATA_KEY")}, nil
	case "file":
		path := os.Getenv("KEEPPAM_DATA_KEY_FILE")
		if path == "" {
			return nil, fmt.Errorf("KEEPPAM_DATA_KEY_FILE required when SOURCE=file")
		}
		return FileKeyProvider{Path: path}, nil
	case "vault":
		addr := os.Getenv("KEEPPAM_VAULT_ADDR")
		if addr == "" {
			return nil, fmt.Errorf("KEEPPAM_VAULT_ADDR required when SOURCE=vault")
		}
		return VaultTransitProvider{
			Addr:  addr,
			Token: os.Getenv("KEEPPAM_VAULT_TOKEN"),
			Path:  os.Getenv("KEEPPAM_VAULT_TRANSIT_PATH"),
		}, nil
	default:
		return nil, fmt.Errorf("KEEPPAM_DATA_KEY_SOURCE must be env|file|vault")
	}
}
