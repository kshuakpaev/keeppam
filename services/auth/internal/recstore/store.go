package recstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store abstracts local disk and optional S3-compatible object storage.
// Writers (guacd/ssh) still use local paths; Store syncs/fetches around them.
type Store interface {
	Backend() string
	LocalRoot() string
	// EnsureLocal makes sure path exists locally (download from S3 if needed).
	EnsureLocal(ctx context.Context, absPath string) error
	// Sync uploads a local file (or guac base + suffixes) to S3 when enabled.
	Sync(ctx context.Context, absPath string) error
	// Exists reports whether recording is available locally or remotely.
	Exists(ctx context.Context, absPath string) bool
}

type Local struct {
	Root string
}

func (l *Local) Backend() string   { return "local" }
func (l *Local) LocalRoot() string { return l.Root }

func (l *Local) EnsureLocal(ctx context.Context, absPath string) error {
	_ = ctx
	_, err := os.Stat(absPath)
	return err
}

func (l *Local) Sync(ctx context.Context, absPath string) error {
	_ = ctx
	_ = absPath
	return nil
}

func (l *Local) Exists(ctx context.Context, absPath string) bool {
	_ = ctx
	_, err := os.Stat(absPath)
	return err == nil
}

// Hybrid keeps local FS for guacd and mirrors to S3.
type Hybrid struct {
	Local *Local
	S3    *S3
}

func (h *Hybrid) Backend() string {
	if h.S3 == nil {
		return "local"
	}
	return "s3"
}
func (h *Hybrid) LocalRoot() string { return h.Local.Root }

func (h *Hybrid) EnsureLocal(ctx context.Context, absPath string) error {
	for _, p := range guacCandidates(absPath) {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	if h.S3 == nil {
		return fmt.Errorf("recording not found")
	}
	var last error
	for _, p := range guacCandidates(absPath) {
		key, err := h.relKey(p)
		if err != nil {
			last = err
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		if err := h.S3.GetToFile(ctx, key, p); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last == nil {
		last = fmt.Errorf("recording not found")
	}
	return last
}

func (h *Hybrid) Sync(ctx context.Context, absPath string) error {
	if h.S3 == nil {
		return nil
	}
	paths := guacCandidates(absPath)
	var first error
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		key, err := h.relKey(p)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if err := h.S3.PutFile(ctx, key, p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (h *Hybrid) Exists(ctx context.Context, absPath string) bool {
	for _, p := range guacCandidates(absPath) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	if h.S3 == nil {
		return false
	}
	key, err := h.relKey(absPath)
	if err != nil {
		return false
	}
	ok, _ := h.S3.Head(ctx, key)
	return ok
}

func (h *Hybrid) relKey(absPath string) (string, error) {
	root := filepath.Clean(h.Local.Root)
	p := filepath.Clean(absPath)
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path outside recordings dir")
	}
	return filepath.ToSlash(rel), nil
}

func guacCandidates(base string) []string {
	out := []string{base}
	for i := 1; i <= 32; i++ {
		out = append(out, fmt.Sprintf("%s.%d", base, i))
	}
	return out
}

type S3 struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	Prefix    string
	PathStyle bool
	Client    *http.Client
}

func (s *S3) objectURL(key string) string {
	key = strings.TrimPrefix(key, "/")
	pref := strings.Trim(s.Prefix, "/")
	if pref != "" {
		key = pref + "/" + key
	}
	ep := strings.TrimRight(s.Endpoint, "/")
	if s.PathStyle {
		return fmt.Sprintf("%s/%s/%s", ep, s.Bucket, key)
	}
	// virtual-hosted
	u, err := url.Parse(ep)
	if err != nil {
		return fmt.Sprintf("%s/%s/%s", ep, s.Bucket, key)
	}
	return fmt.Sprintf("%s://%s.%s/%s", u.Scheme, s.Bucket, u.Host, key)
}

func (s *S3) PutFile(ctx context.Context, key, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.objectURL(key), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(b))
	if err := s.sign(req, b); err != nil {
		return err
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("s3 put %d", resp.StatusCode)
	}
	return nil
}

func (s *S3) GetToFile(ctx context.Context, key, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL(key), nil)
	if err != nil {
		return err
	}
	if err := s.sign(req, nil); err != nil {
		return err
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("s3 get %d", resp.StatusCode)
	}
	_ = os.MkdirAll(filepath.Dir(dest), 0o750)
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func (s *S3) Head(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.objectURL(key), nil)
	if err != nil {
		return false, err
	}
	if err := s.sign(req, nil); err != nil {
		return false, err
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

func (s *S3) http() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (s *S3) sign(req *http.Request, payload []byte) error {
	if s.AccessKey == "" || s.SecretKey == "" {
		return fmt.Errorf("s3 credentials required")
	}
	region := s.Region
	if region == "" {
		region = "us-east-1"
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	host := req.URL.Host
	req.Header.Set("Host", host)

	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	credentialScope := dateStamp + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := aws4SigningKey(s.SecretKey, dateStamp, region, "s3")
	sig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKey, credentialScope, signedHeaders, sig,
	))
	return nil
}

func sha256Hex(b []byte) string {
	if b == nil {
		b = []byte{}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func aws4SigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// NewFromEnv builds Local or Hybrid store.
func NewFromEnv(recordingsDir string) (Store, error) {
	local := &Local{Root: recordingsDir}
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("KEEPPAM_RECORDINGS_BACKEND")))
	if backend == "" || backend == "local" {
		return local, nil
	}
	if backend != "s3" {
		return nil, fmt.Errorf("KEEPPAM_RECORDINGS_BACKEND must be local|s3")
	}
	ep := os.Getenv("KEEPPAM_S3_ENDPOINT")
	bucket := os.Getenv("KEEPPAM_S3_BUCKET")
	if ep == "" || bucket == "" {
		return nil, fmt.Errorf("KEEPPAM_S3_ENDPOINT and KEEPPAM_S3_BUCKET required for s3 backend")
	}
	s3 := &S3{
		Endpoint:  ep,
		Region:    envOr("KEEPPAM_S3_REGION", "us-east-1"),
		Bucket:    bucket,
		AccessKey: os.Getenv("KEEPPAM_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("KEEPPAM_S3_SECRET_KEY"),
		Prefix:    os.Getenv("KEEPPAM_S3_PREFIX"),
		PathStyle: strings.ToLower(os.Getenv("KEEPPAM_S3_PATH_STYLE")) != "false",
	}
	return &Hybrid{Local: local, S3: s3}, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
