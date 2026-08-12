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
	"sort"
	"strconv"
	"strings"
	"time"
)

// Store abstracts local disk and optional S3-compatible object storage.
// Writers (guacd/ssh) still use local paths; Store syncs/fetches around them.
type Store interface {
	Backend() string
	LocalRoot() string
	ObjectLockMode() string
	ObjectLockDays() int
	EnsureLocal(ctx context.Context, absPath string) error
	Sync(ctx context.Context, absPath string) error
	Exists(ctx context.Context, absPath string) bool
	// TryDelete removes local + remote recording. wormProtected=true if S3 Object Lock blocked delete.
	TryDelete(ctx context.Context, absPath string) (deleted bool, wormProtected bool, err error)
	// SetLegalHold toggles S3 Object Lock legal hold (no-op for local).
	SetLegalHold(ctx context.Context, absPath string, on bool) error
}

type Local struct {
	Root string
}

func (l *Local) Backend() string         { return "local" }
func (l *Local) LocalRoot() string       { return l.Root }
func (l *Local) ObjectLockMode() string  { return "" }
func (l *Local) ObjectLockDays() int     { return 0 }

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

func (l *Local) TryDelete(ctx context.Context, absPath string) (bool, bool, error) {
	_ = ctx
	if err := removeLocalRecording(absPath); err != nil {
		return false, false, err
	}
	return true, false, nil
}

func (l *Local) SetLegalHold(ctx context.Context, absPath string, on bool) error {
	_ = ctx
	_ = absPath
	_ = on
	return nil
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
func (h *Hybrid) ObjectLockMode() string {
	if h.S3 == nil {
		return ""
	}
	return h.S3.LockMode
}
func (h *Hybrid) ObjectLockDays() int {
	if h.S3 == nil {
		return 0
	}
	return h.S3.LockDays
}

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

func (h *Hybrid) TryDelete(ctx context.Context, absPath string) (bool, bool, error) {
	_ = removeLocalRecording(absPath)
	if h.S3 == nil {
		return true, false, nil
	}
	worm := false
	deletedRemote := false
	for _, p := range guacCandidates(absPath) {
		key, err := h.relKey(p)
		if err != nil {
			continue
		}
		ok, _ := h.S3.Head(ctx, key)
		if !ok {
			continue
		}
		if err := h.S3.Delete(ctx, key); err != nil {
			if isWORMBlocked(err) {
				worm = true
			}
			continue
		}
		deletedRemote = true
	}
	if worm {
		return false, true, nil
	}
	return deletedRemote || true, false, nil
}

func (h *Hybrid) SetLegalHold(ctx context.Context, absPath string, on bool) error {
	if h.S3 == nil {
		return nil
	}
	var last error
	for _, p := range guacCandidates(absPath) {
		key, err := h.relKey(p)
		if err != nil {
			continue
		}
		ok, _ := h.S3.Head(ctx, key)
		if !ok {
			continue
		}
		if err := h.S3.PutLegalHold(ctx, key, on); err != nil {
			last = err
		}
	}
	return last
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

func removeLocalRecording(path string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		_ = os.RemoveAll(path)
		return nil
	}
	if fi.IsDir() {
		return os.RemoveAll(path)
	}
	_ = os.Remove(path)
	_ = os.Remove(strings.TrimSuffix(path, filepath.Ext(path)) + ".jsonl")
	for i := 1; i <= 32; i++ {
		_ = os.Remove(fmt.Sprintf("%s.%d", path, i))
	}
	return nil
}

func isWORMBlocked(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "accessdenied") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "409") ||
		strings.Contains(msg, "object locked") ||
		strings.Contains(msg, "access denied")
}

type S3 struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	Prefix    string
	PathStyle bool
	LockMode  string // GOVERNANCE | COMPLIANCE | ""
	LockDays  int
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
	if mode := strings.ToUpper(strings.TrimSpace(s.LockMode)); mode == "GOVERNANCE" || mode == "COMPLIANCE" {
		days := s.LockDays
		if days <= 0 {
			days = 90
		}
		until := time.Now().UTC().AddDate(0, 0, days).Format("2006-01-02T15:04:05.000Z")
		req.Header.Set("X-Amz-Object-Lock-Mode", mode)
		req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", until)
	}
	if err := s.sign(req, b); err != nil {
		return err
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("s3 put %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

func (s *S3) Delete(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(key), nil)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("s3 delete %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *S3) PutLegalHold(ctx context.Context, key string, on bool) error {
	status := "OFF"
	if on {
		status = "ON"
	}
	payload := []byte(fmt.Sprintf(`<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></LegalHold>`, status))
	u := s.objectURL(key) + "?legal-hold"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.ContentLength = int64(len(payload))
	req.URL.RawQuery = "legal-hold="
	if err := s.sign(req, payload); err != nil {
		return err
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("s3 legal-hold %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
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

	hdrs := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	for k, vv := range req.Header {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, "x-amz-") || lk == "x-amz-date" || lk == "x-amz-content-sha256" {
			continue
		}
		if len(vv) > 0 {
			hdrs[lk] = strings.TrimSpace(vv[0])
		}
	}
	keys := make([]string, 0, len(hdrs))
	for k := range hdrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonicalHeaders strings.Builder
	for _, k := range keys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(hdrs[k])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders.String(),
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
	lockMode := strings.ToUpper(strings.TrimSpace(os.Getenv("KEEPPAM_S3_OBJECT_LOCK_MODE")))
	switch lockMode {
	case "", "OFF", "NONE":
		lockMode = ""
	case "GOVERNANCE", "COMPLIANCE":
	default:
		return nil, fmt.Errorf("KEEPPAM_S3_OBJECT_LOCK_MODE must be empty|GOVERNANCE|COMPLIANCE")
	}
	lockDays := 90
	if v := strings.TrimSpace(os.Getenv("KEEPPAM_S3_OBJECT_LOCK_DAYS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 36500 {
			return nil, fmt.Errorf("KEEPPAM_S3_OBJECT_LOCK_DAYS must be 1..36500")
		}
		lockDays = n
	}
	s3 := &S3{
		Endpoint:  ep,
		Region:    envOr("KEEPPAM_S3_REGION", "us-east-1"),
		Bucket:    bucket,
		AccessKey: os.Getenv("KEEPPAM_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("KEEPPAM_S3_SECRET_KEY"),
		Prefix:    os.Getenv("KEEPPAM_S3_PREFIX"),
		PathStyle: strings.ToLower(os.Getenv("KEEPPAM_S3_PATH_STYLE")) != "false",
		LockMode:  lockMode,
		LockDays:  lockDays,
	}
	return &Hybrid{Local: local, S3: s3}, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
