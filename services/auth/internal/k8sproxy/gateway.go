package k8sproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/sessionsvc"
)

type Gateway struct {
	addr     string
	public   string
	cert     tls.Certificate
	rdb      *redis.Client
	assets   *assets.Service
	sessions *sessionsvc.Service
	audit    *audit.Service
	live     *sessionsvc.LiveHub

	mu        sync.Mutex
	upstreams map[uuid.UUID]*sessionUpstream
}

type sessionUpstream struct {
	up   *Upstream
	rec  *Recorder
	row  sessionsvc.Session
}

func New(addr, publicURL string, cert tls.Certificate, rdb *redis.Client, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service, live *sessionsvc.LiveHub) *Gateway {
	return &Gateway{
		addr: addr, public: publicURL, cert: cert, rdb: rdb, assets: assetsSvc,
		sessions: sess, audit: aud, live: live, upstreams: map[uuid.UUID]*sessionUpstream{},
	}
}

func (g *Gateway) PublicURL() string {
	if g.public != "" {
		return strings.TrimRight(g.public, "/")
	}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(g.addr, ":"))
	if err != nil {
		if strings.HasPrefix(g.addr, ":") {
			return "https://localhost" + g.addr
		}
		return "https://localhost:16443"
	}
	if host == "" || host == "0.0.0.0" {
		host = "localhost"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func (g *Gateway) ListenAndServe(ctx context.Context) error {
	if g.addr == "" || g.addr == "off" {
		<-ctx.Done()
		return nil
	}
	srv := &http.Server{
		Addr:              g.addr,
		Handler:           g,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{g.cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	ln, err := net.Listen("tcp", g.addr)
	if err != nil {
		return err
	}
	slog.Info("k8s api gateway", "addr", g.addr)
	return srv.Serve(tls.NewListener(ln, srv.TLSConfig))
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	sid, tok, err := ParseBearer(r.Header.Get("Authorization"))
	if err != nil {
		writeK8sStatus(w, http.StatusUnauthorized, "Unauthorized", "missing or invalid bearer token")
		return
	}
	want, err := GetToken(r.Context(), g.rdb, sid)
	if err != nil || want == "" || want != tok {
		writeK8sStatus(w, http.StatusUnauthorized, "Unauthorized", "invalid session token")
		return
	}
	row, err := g.sessions.Get(r.Context(), sid)
	if err != nil || (row.Status != "pending" && row.Status != "active") {
		writeK8sStatus(w, http.StatusUnauthorized, "Unauthorized", "session not active")
		return
	}
	if row.Protocol != "kubectl" {
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", "not a kubectl session")
		return
	}

	watch := r.URL.Query().Get("watch") == "true"
	call := ParseAPIPath(r.Method, r.URL.Path, watch)
	if IsUpgrade(r) || call.Denied() {
		_ = g.audit.Record(r.Context(), &row.UserID, "session.k8s.denied", "session", sid.String(), clientIP(r), "k8s", map[string]any{
			"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
			"subresource": call.Subresource, "reason": "denied_subresource",
		})
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", "exec/attach/port-forward/upgrade denied by KeepPAM")
		return
	}

	up, err := g.ensureUpstream(r.Context(), row)
	if err != nil {
		writeK8sStatus(w, http.StatusBadGateway, "BadGateway", err.Error())
		return
	}
	if row.Status == "pending" {
		_ = g.sessions.MarkActive(r.Context(), sid)
		_ = g.audit.Record(r.Context(), &row.UserID, "session.started", "session", sid.String(), clientIP(r), "k8s", map[string]any{
			"protocol": "kubectl",
		})
	}
	_ = g.sessions.Touch(r.Context(), sid)

	// Never forward client impersonation or original auth.
	r.Header.Del("Authorization")
	r.Header.Del("Impersonate-User")
	r.Header.Del("Impersonate-Group")
	r.Header.Del("Impersonate-Uid")
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "impersonate-") {
			r.Header.Del(k)
		}
	}
	if up.up.Token != "" {
		r.Header.Set("Authorization", "Bearer "+up.up.Token)
	}

	status := 0
	proxy := httputil.NewSingleHostReverseProxy(up.up.Server)
	proxy.Transport = up.up.Transport
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		status = http.StatusBadGateway
		writeK8sStatus(w, status, "BadGateway", "upstream error")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		status = resp.StatusCode
		return nil
	}
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = up.up.Server.Scheme
		req.URL.Host = up.up.Server.Host
		req.Host = up.up.Server.Host
		req.Header.Del("Cookie")
		req.Header.Del("X-Forwarded-For")
	}
	proxy.ServeHTTP(w, r)
	if status == 0 {
		status = http.StatusOK
	}
	if up.rec != nil {
		up.rec.WriteCall(call, r.Method, r.URL.Path, status)
	}
	_ = g.sessions.AddEvent(r.Context(), sid, "k8s", map[string]any{
		"verb": call.Verb, "resource": call.Resource, "api_group": call.APIGroup,
		"namespace": call.Namespace, "name": call.Name, "status": status, "watch": call.Watch,
	})
	_ = g.audit.Record(r.Context(), &row.UserID, "session.k8s", "session", sid.String(), clientIP(r), "k8s", map[string]any{
		"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
		"name": call.Name, "status": status,
	})
	if g.live != nil {
		g.live.FanoutSQL(r.Context(), sid, map[string]any{
			"type": "k8s", "verb": call.Verb, "resource": call.Resource,
			"namespace": call.Namespace, "name": call.Name, "status": status,
		})
	}
}

func (g *Gateway) ensureUpstream(ctx context.Context, row sessionsvc.Session) (*sessionUpstream, error) {
	g.mu.Lock()
	if u, ok := g.upstreams[row.ID]; ok {
		g.mu.Unlock()
		return u, nil
	}
	g.mu.Unlock()

	creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
	if err != nil {
		return nil, err
	}
	up, err := BuildUpstream(creds)
	if err != nil {
		return nil, err
	}
	rec, err := NewRecorder(row.RecordingPath, row.ID)
	if err != nil {
		slog.Warn("k8s recorder", "err", err)
	}
	su := &sessionUpstream{up: up, rec: rec, row: row}
	g.mu.Lock()
	if existing, ok := g.upstreams[row.ID]; ok {
		g.mu.Unlock()
		if rec != nil {
			rec.Close()
		}
		return existing, nil
	}
	g.upstreams[row.ID] = su
	g.mu.Unlock()
	return su, nil
}

func (g *Gateway) DropSession(id uuid.UUID) {
	g.mu.Lock()
	u := g.upstreams[id]
	delete(g.upstreams, id)
	g.mu.Unlock()
	if u != nil && u.rec != nil {
		u.rec.Close()
	}
}

func writeK8sStatus(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    msg,
		"reason":     reason,
		"code":       code,
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func DefaultPublicURL(corsOrigin, addr string) string {
	host := "localhost"
	if corsOrigin != "" {
		u := strings.TrimPrefix(strings.TrimPrefix(corsOrigin, "https://"), "http://")
		if h, _, err := net.SplitHostPort(u); err == nil {
			host = h
		} else {
			host = strings.Split(u, "/")[0]
		}
	}
	port := "16443"
	if _, p, err := net.SplitHostPort(strings.TrimPrefix(addr, ":")); err == nil && p != "" {
		port = p
	} else if strings.HasPrefix(addr, ":") {
		port = strings.TrimPrefix(addr, ":")
	}
	return fmt.Sprintf("https://%s:%s", host, port)
}
