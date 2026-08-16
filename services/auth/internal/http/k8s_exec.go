package httpapi

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleK8sExecWS(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	authSess, err := s.sessions.Get(r.Context(), c.Value)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if u, err := s.auth.Me(r.Context(), authSess.UserID); err == nil {
		authSess.Roles = u.Roles
		authSess.Permissions = u.Permissions
	}
	if !rbac.HasPermission(authSess.Permissions, "sessions.connect") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if s.k8s == nil {
		writeErr(w, http.StatusServiceUnavailable, "k8s gateway disabled")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if authSess.UserID != row.UserID && !rbac.HasPermission(authSess.Permissions, "users.write") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "kubectl" {
		writeErr(w, http.StatusBadRequest, "not a kubectl session")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusGone, "session ended")
		return
	}

	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	pod := strings.TrimSpace(r.URL.Query().Get("pod"))
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	cmd := r.URL.Query()["command"]
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh"}
	}
	cols, rowsN := 120, 40
	if v := r.URL.Query().Get("cols"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			cols = n
		}
	}
	if v := r.URL.Query().Get("rows"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			rowsN = n
		}
	}

	upConn, err := s.k8s.DialExec(r.Context(), row, ns, pod, container, cmd, true)
	if err != nil {
		code := k8sproxy.HTTPStatus(err)
		if code < 400 {
			code = http.StatusBadGateway
		}
		writeErr(w, code, err.Error())
		return
	}
	defer upConn.Close()

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("k8s exec ws upgrade", "err", err)
		return
	}
	defer conn.Close()
	_ = writeWSJSON(conn, map[string]string{"type": "ready"})
	k8sproxy.ProxyExec(conn, upConn, cols, rowsN)
}

func (s *Server) handleK8sAttachWS(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	authSess, err := s.sessions.Get(r.Context(), c.Value)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if u, err := s.auth.Me(r.Context(), authSess.UserID); err == nil {
		authSess.Roles = u.Roles
		authSess.Permissions = u.Permissions
	}
	if !rbac.HasPermission(authSess.Permissions, "sessions.connect") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if s.k8s == nil {
		writeErr(w, http.StatusServiceUnavailable, "k8s gateway disabled")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if authSess.UserID != row.UserID && !rbac.HasPermission(authSess.Permissions, "users.write") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "kubectl" {
		writeErr(w, http.StatusBadRequest, "not a kubectl session")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusGone, "session ended")
		return
	}

	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	pod := strings.TrimSpace(r.URL.Query().Get("pod"))
	container := strings.TrimSpace(r.URL.Query().Get("container"))
	cols, rowsN := 120, 40
	if v := r.URL.Query().Get("cols"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			cols = n
		}
	}
	if v := r.URL.Query().Get("rows"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			rowsN = n
		}
	}

	upConn, err := s.k8s.DialAttach(r.Context(), row, ns, pod, container, true)
	if err != nil {
		code := k8sproxy.HTTPStatus(err)
		if code < 400 {
			code = http.StatusBadGateway
		}
		writeErr(w, code, err.Error())
		return
	}
	defer upConn.Close()

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("k8s attach ws upgrade", "err", err)
		return
	}
	defer conn.Close()
	_ = writeWSJSON(conn, map[string]string{"type": "ready"})
	k8sproxy.ProxyExec(conn, upConn, cols, rowsN)
}
