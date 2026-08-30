package digitalidlab

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	ClientID     = "keeppam-digitalid-lab"
	ClientSecret = "keeppam-digitalid-lab-secret"
	codeTTL      = 5 * time.Minute
	tokenTTL     = 15 * time.Minute
)

// Preset is filled into auth_settings for the in-product Digital ID lab IdP.
type Preset struct {
	AuthorizeURL  string `json:"authorize_url"`
	TokenURL      string `json:"token_url"`
	UserinfoURL   string `json:"userinfo_url"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	UsernameClaim string `json:"username_claim"`
	EmailClaim    string `json:"email_claim"`
	NameClaim     string `json:"name_claim"`
}

func LoopbackAPI(httpAddr string) string {
	addr := strings.TrimSpace(httpAddr)
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func MakePreset(publicBase, httpAddr string) Preset {
	pub := strings.TrimRight(strings.TrimSpace(publicBase), "/")
	loop := LoopbackAPI(httpAddr)
	authz := loop + "/api/v1/auth/digitalid-lab/authorize"
	if pub != "" {
		authz = pub + "/api/v1/auth/digitalid-lab/authorize"
	}
	return Preset{
		AuthorizeURL:  authz,
		TokenURL:      loop + "/api/v1/auth/digitalid-lab/token",
		UserinfoURL:   loop + "/api/v1/auth/digitalid-lab/userinfo",
		ClientID:      ClientID,
		ClientSecret:  ClientSecret,
		UsernameClaim: "iin",
		EmailClaim:    "email",
		NameClaim:     "name",
	}
}

type KV interface {
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	GetDel(ctx context.Context, key string) ([]byte, error)
}

type MemKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func NewMemKV() *MemKV { return &MemKV{data: map[string][]byte{}} }

func (m *MemKV) Set(_ context.Context, key string, val []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), val...)
	return nil
}

func (m *MemKV) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return append([]byte(nil), v...), nil
}

func (m *MemKV) GetDel(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	delete(m.data, key)
	return v, nil
}

type RedisKV struct {
	C *redis.Client
}

func (r RedisKV) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	if r.C == nil {
		return fmt.Errorf("redis not configured")
	}
	return r.C.Set(ctx, key, val, ttl).Err()
}

func (r RedisKV) Get(ctx context.Context, key string) ([]byte, error) {
	if r.C == nil {
		return nil, fmt.Errorf("not found")
	}
	b, err := r.C.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (r RedisKV) GetDel(ctx context.Context, key string) ([]byte, error) {
	if r.C == nil {
		return nil, fmt.Errorf("not found")
	}
	b, err := r.C.GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return b, nil
}

type Lab struct {
	KV KV
}

type codeRec struct {
	IIN         string `json:"iin"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Challenge   string `json:"challenge"`
	Method      string `json:"method"`
	RedirectURI string `json:"redirect_uri"`
	ClientID    string `json:"client_id"`
}

func (l *Lab) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		q = r.Form
	}
	clientID := strings.TrimSpace(first(q, "client_id"))
	redirect := strings.TrimSpace(first(q, "redirect_uri"))
	state := first(q, "state")
	challenge := first(q, "code_challenge")
	method := first(q, "code_challenge_method")
	if clientID != ClientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if redirect == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, authorizeHTML(q))
		return
	}
	iin := digits(first(q, "iin"))
	if iin == "" {
		iin = "900101300123"
	}
	name := strings.TrimSpace(first(q, "name"))
	if name == "" {
		name = "Digital ID Lab"
	}
	email := strings.TrimSpace(first(q, "email"))
	if email == "" {
		email = iin + "@digitalid.lab"
	}
	code := randomToken(16)
	raw, _ := json.Marshal(codeRec{
		IIN: iin, Name: name, Email: email,
		Challenge: challenge, Method: method,
		RedirectURI: redirect, ClientID: clientID,
	})
	if err := l.KV.Set(r.Context(), "digitalidlab:code:"+code, raw, codeTTL); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	if state != "" {
		qq.Set("state", state)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (l *Lab) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	if id != ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(ClientSecret)) != 1 {
		writeOAuthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeOAuthErr(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	code := r.Form.Get("code")
	raw, err := l.KV.GetDel(r.Context(), "digitalidlab:code:"+code)
	if err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	var rec codeRec
	if err := json.Unmarshal(raw, &rec); err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if redir := r.Form.Get("redirect_uri"); redir != "" && redir != rec.RedirectURI {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if rec.Challenge != "" {
		if !verifyPKCE(r.Form.Get("code_verifier"), rec.Challenge, rec.Method) {
			writeOAuthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}
	tok := randomToken(24)
	user, _ := json.Marshal(map[string]string{
		"iin": rec.IIN, "email": rec.Email, "name": rec.Name, "sub": rec.IIN,
	})
	if err := l.KV.Set(r.Context(), "digitalidlab:tok:"+tok, user, tokenTTL); err != nil {
		writeOAuthErr(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(tokenTTL.Seconds()),
	})
}

func (l *Lab) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, err := l.KV.Get(r.Context(), "digitalidlab:tok:"+strings.TrimSpace(strings.TrimPrefix(h, p)))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method == "" || strings.EqualFold(method, "plain") {
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func writeOAuthErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func first(q url.Values, k string) string { return strings.TrimSpace(q.Get(k)) }

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}

func authorizeHTML(q url.Values) string {
	esc := func(k string) string { return html.EscapeString(q.Get(k)) }
	return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>KeepPAM Digital ID (lab)</title>
<style>body{font-family:sans-serif;max-width:28rem;margin:2rem auto;padding:0 1rem}
label{display:block;margin:.6rem 0 .2rem}input{width:100%;padding:.4rem;box-sizing:border-box}
button{margin-top:1rem;padding:.5rem 1rem}</style></head><body>
<h1>Digital ID (лаборатория KeepPAM)</h1>
<p>Локальный IdP без интернета и без URL партнёра. На поставке замените URL на контур Digital ID заказчика.</p>
<form method="post">
<input type="hidden" name="client_id" value="` + esc("client_id") + `">
<input type="hidden" name="redirect_uri" value="` + esc("redirect_uri") + `">
<input type="hidden" name="state" value="` + esc("state") + `">
<input type="hidden" name="code_challenge" value="` + esc("code_challenge") + `">
<input type="hidden" name="code_challenge_method" value="` + esc("code_challenge_method") + `">
<label>ИИН</label><input name="iin" value="900101300123" inputmode="numeric" autocomplete="off">
<label>ФИО</label><input name="name" value="Digital ID Lab">
<label>Email</label><input name="email" value="900101300123@digitalid.lab">
<button type="submit">Войти</button>
</form></body></html>`
}
