package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func kmsHTTP(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func decodeDEK(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, fmt.Errorf("KMS plaintext empty")
	}
	var (
		key []byte
		err error
	)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		key, err = enc.DecodeString(b64)
		if err == nil {
			break
		}
	}
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("KMS plaintext must be base64 of 32 bytes")
	}
	return key, nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func requireCiphertext() (string, error) {
	ct := firstEnv("KEEPPAM_KMS_CIPHERTEXT", "KEEPPAM_VAULT_CIPHERTEXT")
	if ct == "" {
		return "", fmt.Errorf("KEEPPAM_KMS_CIPHERTEXT required")
	}
	return ct, nil
}

// AWSKMSProvider unwraps a 32-byte DEK via AWS KMS Decrypt (SigV4, no SDK).
type AWSKMSProvider struct {
	Region     string
	AccessKey  string
	SecretKey  string
	SessionTok string
	Endpoint   string
	KeyID      string
	Ciphertext string
	HTTPClient *http.Client
}

func (p AWSKMSProvider) Source() string { return "aws" }

func (p AWSKMSProvider) Load(ctx context.Context) ([]byte, error) {
	region := strings.TrimSpace(p.Region)
	if region == "" {
		region = "us-east-1"
	}
	if strings.TrimSpace(p.AccessKey) == "" || strings.TrimSpace(p.SecretKey) == "" {
		return nil, fmt.Errorf("KEEPPAM_AWS_ACCESS_KEY and KEEPPAM_AWS_SECRET_KEY required")
	}
	ct := strings.TrimSpace(p.Ciphertext)
	if ct == "" {
		return nil, fmt.Errorf("KEEPPAM_KMS_CIPHERTEXT required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(p.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://kms." + region + ".amazonaws.com"
	}
	bodyMap := map[string]any{"CiphertextBlob": ct}
	if kid := strings.TrimSpace(p.KeyID); kid != "" {
		bodyMap["KeyId"] = kid
	}
	payload, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.Decrypt")
	signAWS4(req, payload, p.AccessKey, p.SecretKey, p.SessionTok, region, "kms")
	resp, err := kmsHTTP(p.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws kms dial: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("aws kms %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Plaintext string `json:"Plaintext"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return decodeDEK(out.Plaintext)
}

// GCPKMSProvider unwraps a 32-byte DEK via Cloud KMS decrypt REST.
type GCPKMSProvider struct {
	KeyName     string
	AccessToken string
	Endpoint    string
	MetadataURL string
	Ciphertext  string
	HTTPClient  *http.Client
}

func (p GCPKMSProvider) Source() string { return "gcp" }

func (p GCPKMSProvider) Load(ctx context.Context) ([]byte, error) {
	name := strings.TrimSpace(p.KeyName)
	if name == "" {
		return nil, fmt.Errorf("KEEPPAM_GCP_KMS_KEY required")
	}
	ct := strings.TrimSpace(p.Ciphertext)
	if ct == "" {
		return nil, fmt.Errorf("KEEPPAM_KMS_CIPHERTEXT required")
	}
	token := strings.TrimSpace(p.AccessToken)
	if token == "" {
		var err error
		token, err = p.gcpToken(ctx)
		if err != nil {
			return nil, err
		}
	}
	endpoint := strings.TrimRight(strings.TrimSpace(p.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://cloudkms.googleapis.com"
	}
	payload, err := json.Marshal(map[string]string{"ciphertext": ct})
	if err != nil {
		return nil, err
	}
	u := endpoint + "/v1/" + strings.TrimPrefix(name, "/") + ":decrypt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := kmsHTTP(p.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp kms dial: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp kms %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return decodeDEK(out.Plaintext)
}

func (p GCPKMSProvider) gcpToken(ctx context.Context) (string, error) {
	meta := strings.TrimSpace(p.MetadataURL)
	if meta == "" {
		meta = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := kmsHTTP(p.HTTPClient).Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp metadata token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("gcp metadata %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return "", err
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return "", fmt.Errorf("gcp metadata: empty access_token")
	}
	return tok.AccessToken, nil
}

// AzureKVProvider unwraps a 32-byte DEK via Key Vault unwrapkey/decrypt.
type AzureKVProvider struct {
	VaultURL     string
	KeyName      string
	KeyVersion   string
	Op           string
	Alg          string
	Token        string
	TokenURL     string
	TenantID     string
	ClientID     string
	ClientSecret string
	Ciphertext   string
	HTTPClient   *http.Client
}

func (p AzureKVProvider) Source() string { return "azure" }

func (p AzureKVProvider) Load(ctx context.Context) ([]byte, error) {
	vault := strings.TrimRight(strings.TrimSpace(p.VaultURL), "/")
	name := strings.TrimSpace(p.KeyName)
	if vault == "" || name == "" {
		return nil, fmt.Errorf("KEEPPAM_AZURE_VAULT_URL and KEEPPAM_AZURE_KEY_NAME required")
	}
	ct := strings.TrimSpace(p.Ciphertext)
	if ct == "" {
		return nil, fmt.Errorf("KEEPPAM_KMS_CIPHERTEXT required")
	}
	token := strings.TrimSpace(p.Token)
	if token == "" {
		var err error
		token, err = p.azureToken(ctx)
		if err != nil {
			return nil, err
		}
	}
	op := strings.ToLower(strings.TrimSpace(p.Op))
	if op == "" {
		op = "unwrap"
	}
	action := "unwrapkey"
	if op == "decrypt" {
		action = "decrypt"
	}
	alg := strings.TrimSpace(p.Alg)
	if alg == "" {
		alg = "RSA-OAEP-256"
	}
	path := "/keys/" + url.PathEscape(name)
	if ver := strings.TrimSpace(p.KeyVersion); ver != "" {
		path += "/" + url.PathEscape(ver)
	}
	path += "/" + action
	u := vault + path + "?api-version=7.4"
	payload, err := json.Marshal(map[string]string{"alg": alg, "value": ct})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := kmsHTTP(p.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure kv dial: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("azure kv %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return decodeDEK(out.Value)
}

func (p AzureKVProvider) azureToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(p.ClientID) == "" || strings.TrimSpace(p.ClientSecret) == "" {
		return "", fmt.Errorf("KEEPPAM_AZURE_TOKEN or client credentials required")
	}
	tokenURL := strings.TrimSpace(p.TokenURL)
	if tokenURL == "" {
		tenant := strings.TrimSpace(p.TenantID)
		if tenant == "" {
			return "", fmt.Errorf("KEEPPAM_AZURE_TENANT_ID required")
		}
		tokenURL = "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	form.Set("scope", "https://vault.azure.net/.default")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := kmsHTTP(p.HTTPClient).Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token dial: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure token %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return "", err
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return "", fmt.Errorf("azure token: empty access_token")
	}
	return tok.AccessToken, nil
}
