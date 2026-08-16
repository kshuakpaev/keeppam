package k8sproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/policy"
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
	policy   *policy.Service
	rolesOf  func(context.Context, uuid.UUID) []string
	groupsOf func(context.Context, uuid.UUID) []string
	trusted  []string

	mu        sync.Mutex
	upstreams map[uuid.UUID]*sessionUpstream
}

type sessionUpstream struct {
	up                *Upstream
	vaultTok          string
	trOn              bool
	tokenExp          time.Time
	saNS              string
	saName            string
	ttl               time.Duration
	impersonateUser   string
	impersonateGroups []string
	impersonateUID    string
	bindSecretNS      string
	bindSecretName    string
	bindUID           string
	rec               *Recorder
	row               sessionsvc.Session
}

func New(addr, publicURL string, cert tls.Certificate, rdb *redis.Client, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service, live *sessionsvc.LiveHub) *Gateway {
	return &Gateway{
		addr: addr, public: publicURL, cert: cert, rdb: rdb, assets: assetsSvc,
		sessions: sess, audit: aud, live: live, upstreams: map[uuid.UUID]*sessionUpstream{},
	}
}

func (g *Gateway) SetPolicy(p *policy.Service) {
	g.policy = p
}

func (g *Gateway) SetRoles(fn func(context.Context, uuid.UUID) []string) {
	g.rolesOf = fn
}

func (g *Gateway) SetGroups(fn func(context.Context, uuid.UUID) []string) {
	g.groupsOf = fn
}

func (g *Gateway) SetTrustedProxies(cidrs []string) {
	g.trusted = cidrs
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
		_ = g.audit.Record(r.Context(), &row.UserID, "session.k8s.denied", "session", sid.String(), g.clientIP(r), "k8s", map[string]any{
			"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
			"subresource": call.Subresource, "reason": "denied_subresource",
		})
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", "exec/attach/port-forward/upgrade denied by KeepPAM")
		return
	}
	if ok, reason := NamespaceAllowed(row.K8sNamespaces, call); !ok {
		_ = g.audit.Record(r.Context(), &row.UserID, "session.k8s.denied", "session", sid.String(), g.clientIP(r), "k8s", map[string]any{
			"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
			"name": call.Name, "reason": reason,
		})
		msg := "namespace not allowed by KeepPAM policy"
		if reason == "cluster_scope_denied" {
			msg = "cluster-scoped request denied by KeepPAM namespace ACL"
		}
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", msg)
		return
	}
	if msg, deny := g.denyHTTPACL(r.Context(), row, r.Method, r.URL.Path, g.clientIP(r)); deny {
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", msg)
		return
	}
	if msg, deny := g.denyOpRisk(r.Context(), row, call, g.clientIP(r)); deny {
		writeK8sStatus(w, http.StatusForbidden, "Forbidden", msg)
		return
	}
	if NeedsNamespaceListFilter(row.K8sNamespaces, call) {
		if row.Status == "pending" {
			_ = g.sessions.MarkActive(r.Context(), sid)
			_ = g.audit.Record(r.Context(), &row.UserID, "session.started", "session", sid.String(), g.clientIP(r), "k8s", map[string]any{
				"protocol": "kubectl",
			})
		}
		_ = g.sessions.Touch(r.Context(), sid)
		body := SyntheticNamespaceList(row.K8sNamespaces, wantsTable(r.Header.Get("Accept")))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		g.noteCall(r.Context(), row, call, r.Method, r.URL.Path, http.StatusOK)
		return
	}

	up, err := g.ensureUpstream(r.Context(), row)
	if err != nil {
		writeK8sStatus(w, http.StatusBadGateway, "BadGateway", err.Error())
		return
	}
	if row.Status == "pending" {
		_ = g.sessions.MarkActive(r.Context(), sid)
		_ = g.audit.Record(r.Context(), &row.UserID, "session.started", "session", sid.String(), g.clientIP(r), "k8s", map[string]any{
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
	if up.impersonateUser != "" {
		ApplyImpersonate(r.Header, up.impersonateUser, up.impersonateGroups, up.impersonateUID)
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
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.EqualFold(call.Resource, "secrets") {
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			if err != nil {
				return err
			}
			red := RedactSecretJSON(raw)
			resp.Body = io.NopCloser(bytes.NewReader(red))
			resp.ContentLength = int64(len(red))
			resp.Header.Set("Content-Length", strconv.Itoa(len(red)))
			resp.Header.Del("Content-Encoding")
		}
		return nil
	}
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = up.up.Server.Scheme
		req.URL.Host = up.up.Server.Host
		req.Host = up.up.Server.Host
		req.Header.Del("Cookie")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("Accept-Encoding")
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
	_ = g.audit.Record(r.Context(), &row.UserID, "session.k8s", "session", sid.String(), g.clientIP(r), "k8s", map[string]any{
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
		refresh := u.trOn && time.Now().After(u.tokenExp.Add(-30*time.Second))
		g.mu.Unlock()
		if refresh {
			if err := g.remint(ctx, u); err != nil {
				return nil, err
			}
		}
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
	su := &sessionUpstream{up: up, vaultTok: up.Token, row: row}
	if creds.Account.K8sImpersonate {
		uname := strings.TrimSpace(row.Username)
		if uname == "" {
			return nil, fmt.Errorf("impersonate: session username empty")
		}
		var roles, pamGroups []string
		if g.rolesOf != nil {
			roles = g.rolesOf(ctx, row.UserID)
		}
		if g.groupsOf != nil {
			pamGroups = g.groupsOf(ctx, row.UserID)
		}
		su.impersonateUser = ImpersonateUser(creds.Account.K8sImpersonatePrefix, uname)
		su.impersonateGroups = ImpersonateGroups(roles, pamGroups)
		su.impersonateUID = row.UserID.String()
		_ = g.audit.Record(ctx, &row.UserID, "session.k8s.impersonate", "session", row.ID.String(), "", "k8s", map[string]any{
			"impersonate_user": su.impersonateUser, "groups": su.impersonateGroups,
			"namespaces": NormalizeNamespaces(row.K8sNamespaces),
		})
	} else if creds.Account.TokenRequestEnabled {
		ns, name := BindSAName(creds.Account, row.Username)
		ttl := ClampTokenTTL(creds.Account.TokenTTLSeconds)
		spec := TokenRequestSpec{Namespace: ns, Name: name, TTL: ttl}
		vaultUp := *up
		if creds.Account.K8sBindUser {
			if strings.TrimSpace(row.Username) == "" {
				return nil, fmt.Errorf("bind-user: session username empty")
			}
			if _, _, err := EnsureSA(ctx, &vaultUp, ns, name, row.Username); err != nil {
				return nil, fmt.Errorf("ensure sa: %w", err)
			}
			secName := BindSecretName(row.ID)
			uid, err := EnsureBindSecret(ctx, &vaultUp, ns, secName, row.ID.String())
			if err != nil {
				return nil, fmt.Errorf("bind secret: %w", err)
			}
			spec.Bound = &BoundRef{Kind: "Secret", APIVersion: "v1", Name: secName, UID: uid}
			su.bindSecretNS, su.bindSecretName, su.bindUID = ns, secName, uid
		}
		tr, err := RequestToken(ctx, up, spec)
		if err != nil {
			return nil, fmt.Errorf("token request: %w", err)
		}
		up.Token = tr.Token
		su.trOn = true
		su.tokenExp = tr.ExpiresAt
		su.saNS, su.saName, su.ttl = ns, name, ttl
		payload := map[string]any{
			"sa_namespace": ns, "sa_name": name, "expires_at": tr.ExpiresAt.UTC().Format(time.RFC3339),
			"bind_user": creds.Account.K8sBindUser,
		}
		if spec.Bound != nil {
			payload["bound_kind"] = spec.Bound.Kind
			payload["bound_name"] = spec.Bound.Name
		}
		_ = g.audit.Record(ctx, &row.UserID, "session.k8s.token_requested", "session", row.ID.String(), "", "k8s", payload)
	}
	rec, err := NewRecorder(row.RecordingPath, row.ID)
	if err != nil {
		slog.Warn("k8s recorder", "err", err)
	}
	su.rec = rec
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

func (g *Gateway) remint(ctx context.Context, u *sessionUpstream) error {
	mint := *u.up
	mint.Token = u.vaultTok
	spec := TokenRequestSpec{Namespace: u.saNS, Name: u.saName, TTL: u.ttl}
	if u.bindSecretName != "" && u.bindUID != "" {
		spec.Bound = &BoundRef{Kind: "Secret", APIVersion: "v1", Name: u.bindSecretName, UID: u.bindUID}
	}
	tr, err := RequestToken(ctx, &mint, spec)
	if err != nil {
		return fmt.Errorf("token request: %w", err)
	}
	g.mu.Lock()
	u.up.Token = tr.Token
	u.tokenExp = tr.ExpiresAt
	g.mu.Unlock()
	_ = g.audit.Record(ctx, &u.row.UserID, "session.k8s.token_requested", "session", u.row.ID.String(), "", "k8s", map[string]any{
		"sa_namespace": u.saNS, "sa_name": u.saName, "expires_at": tr.ExpiresAt.UTC().Format(time.RFC3339), "refresh": true,
		"bound_name": u.bindSecretName,
	})
	return nil
}

func (g *Gateway) DropSession(id uuid.UUID) {
	g.mu.Lock()
	u := g.upstreams[id]
	delete(g.upstreams, id)
	g.mu.Unlock()
	if u != nil && u.rec != nil {
		u.rec.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ns, name := "", ""
	var vault *Upstream
	if u != nil {
		ns, name = u.bindSecretNS, u.bindSecretName
		if u.up != nil {
			cp := *u.up
			cp.Token = u.vaultTok
			vault = &cp
		}
	}
	if name == "" {
		name = BindSecretName(id)
		row, err := g.sessions.Get(ctx, id)
		if err == nil && row.Protocol == "kubectl" {
			creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
			if err == nil && creds.Account.K8sBindUser {
				ns, _ = BindSAName(creds.Account, row.Username)
				if up, err := BuildUpstream(creds); err == nil {
					vault = up
				}
			}
		}
	}
	if vault != nil && ns != "" && name != "" {
		if err := DeleteBindSecret(ctx, vault, ns, name); err != nil {
			slog.Warn("k8s bind secret delete", "session", id.String(), "err", err)
		}
	}
}

func (g *Gateway) denyHTTPACL(ctx context.Context, row sessionsvc.Session, method, path, ip string) (string, bool) {
	if g == nil || g.policy == nil {
		return "", false
	}
	if row.HTTPPolicyPackID != nil {
		pack, err := g.policy.GetHTTPPack(ctx, *row.HTTPPolicyPackID)
		if err == nil {
			ok, why := policy.MatchHTTP(pack, method, path)
			if !ok {
				_ = g.audit.Record(ctx, &row.UserID, "session.http.denied", "session", row.ID.String(), ip, "k8s", map[string]any{
					"method": method, "path": path, "reason": why, "pack": pack.Name, "mode": pack.Mode,
				})
				_ = g.sessions.AddEvent(ctx, row.ID, "http_denied", map[string]any{
					"method": method, "path": path, "reason": why, "pack": pack.Name,
				})
				return why, true
			}
		}
	}
	if row.AppObjectPackID != nil {
		pack, err := g.policy.GetAppObjectPack(ctx, *row.AppObjectPackID)
		if err == nil {
			d := policy.MatchAppObject(pack, method, path)
			if !d.Allowed {
				action := "session.app.denied"
				evt := "app_denied"
				if d.Code == "approval_required" {
					action = "session.app.approval_required"
					evt = "app_approval"
				}
				payload := map[string]any{
					"method": method, "path": path, "reason": d.Reason, "pack": pack.Name,
					"object": d.Object, "action": d.Action, "code": d.Code,
				}
				_ = g.audit.Record(ctx, &row.UserID, action, "session", row.ID.String(), ip, "k8s", payload)
				_ = g.sessions.AddEvent(ctx, row.ID, evt, payload)
				return d.Reason, true
			}
		}
	}
	return "", false
}

func (g *Gateway) denyOpRisk(ctx context.Context, row sessionsvc.Session, call APICall, ip string) (string, bool) {
	if g == nil || g.policy == nil {
		return "", false
	}
	op := policy.K8sOperation(call.Verb, call.Subresource)
	if op == "" {
		return "", false
	}
	var roles []string
	if g.rolesOf != nil {
		roles = g.rolesOf(ctx, row.UserID)
	}
	ev, err := g.policy.CheckOpRisk(ctx, policy.AccessCheck{
		UserID: row.UserID, AssetID: row.AssetID, RoleNames: roles,
		TicketID: row.TicketID, ClientIP: ip, Operation: op, Snapshot: row.PolicySnapshot,
	})
	if err != nil || ev.OK {
		return "", false
	}
	msg := ev.DenyMessage()
	_ = g.audit.Record(ctx, &row.UserID, "session.k8s.denied", "session", row.ID.String(), ip, "k8s", map[string]any{
		"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
		"name": call.Name, "reason": "risk", "operation": op, "risk_score": ev.RiskScore, "max_risk": ev.MaxRisk,
	})
	_ = g.sessions.AddEvent(ctx, row.ID, "risk", map[string]any{
		"verb": call.Verb, "resource": call.Resource, "namespace": call.Namespace,
		"reason": msg, "operation": op, "risk_score": ev.RiskScore,
	})
	return msg, true
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

func (g *Gateway) clientIP(r *http.Request) string {
	if g == nil {
		return geoip.RequestClientIP(r, nil)
	}
	return geoip.RequestClientIP(r, g.trusted)
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
