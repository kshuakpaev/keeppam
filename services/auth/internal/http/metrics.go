package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/keeppam/auth/internal/obs"
)

func (s *Server) metricsMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/livez" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			next.ServeHTTP(w, r)
			return
		}
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		route := r.URL.Path
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		code := ww.Status()
		if code == 0 {
			code = http.StatusOK
		}
		d := time.Since(start)
		obs.Default.ObserveHTTP(route, code, d)
		switch route {
		case "/api/v1/auth/login":
			obs.Default.ObserveAuth("password", d)
		case "/api/v1/auth/mfa/verify":
			obs.Default.ObserveAuth("mfa", d)
		case "/api/v1/auth/mfa/webauthn/finish":
			obs.Default.ObserveAuth("webauthn", d)
		case "/api/v1/auth/oidc/callback":
			obs.Default.ObserveAuth("oidc", d)
		case "/api/v1/auth/saml/acs", "/api/v1/auth/saml/idp/{slug}/acs":
			obs.Default.ObserveAuth("saml", d)
		}
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.analytics != nil {
		if snap, err := s.analytics.SLO(r.Context()); err == nil {
			obs.Default.SetActiveSessions(int64(snap.ActiveSessions))
			if snap.AuditExportLagSeconds != nil {
				obs.Default.SetAuditLag(float64(*snap.AuditExportLagSeconds), true)
			} else {
				obs.Default.SetAuditLag(0, false)
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	obs.Default.WritePrometheus(w)
}

func (s *Server) handleAnalyticsSLO(w http.ResponseWriter, r *http.Request) {
	out, err := s.analytics.SLO(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
