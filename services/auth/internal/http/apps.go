package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/appaccess"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) handleGetAppIntegration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	in, err := s.apps.GetIntegration(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handlePutAppIntegration(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in appaccess.UpsertInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.apps.UpsertIntegration(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAppAccess(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		AccountID string `json:"account_id"`
		TicketID  string `json:"ticket_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var accountID uuid.UUID
	if body.AccountID != "" {
		accountID, err = uuid.Parse(body.AccountID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid account_id")
			return
		}
	}
	bypass := rbac.HasPermission(sess.Permissions, "users.write")
	lease, err := s.apps.RequestAccess(r.Context(), sess.UserID, assetID, accountID, sess.Roles, bypass, body.TicketID, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func (s *Server) handleSessionApp(w http.ResponseWriter, r *http.Request) {
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
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if row.UserID != authSess.UserID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "https" {
		writeErr(w, http.StatusBadRequest, "not an https session")
		return
	}
	if s.apps.IsIsolated(r.Context(), row.AssetID) || row.Isolated {
		writeErr(w, http.StatusBadRequest, "isolated sessions use /sessions/{id}/guac")
		return
	}
	if !s.apps.NeedsFullRecording(r.Context(), row.AssetID) {
		writeErr(w, http.StatusBadRequest, "asset recording_mode is not full")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusConflict, "session not connectable")
		return
	}
	creds, err := s.assets.GetTargetCreds(r.Context(), row.AssetID, row.AccountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	integ, err := s.apps.GetIntegration(r.Context(), row.AssetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	rec, err := appaccess.NewProxyRecorder(row.RecordingPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	proxy, err := appaccess.ReverseProxy(creds, integ, rec, id)
	if err != nil {
		_ = rec.Close()
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	justStarted := row.Status == "pending"
	if justStarted {
		_ = s.sessionsvc.MarkActive(r.Context(), id)
		_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{
			"protocol": "https", "via": "http-proxy", "asset": creds.Asset.Name,
		})
	}

	unregister := s.live.Register(id, func() {})
	var once sync.Once
	finish := func() {
		once.Do(func() {
			unregister()
			_ = rec.Close()
		})
	}
	defer finish()

	hbStop := make(chan struct{})
	defer close(hbStop)
	go sessionsvc.Heartbeat(r.Context(), s.sessionsvc, id, 30*time.Second, hbStop)

	r2 := r.Clone(r.Context())
	prefix := "/api/v1/sessions/" + id.String() + "/app"
	if p := r.URL.Path; len(p) >= len(prefix) {
		r2.URL.Path = p[len(prefix):]
		if r2.URL.Path == "" {
			r2.URL.Path = "/"
		}
	}
	proxy.ServeHTTP(w, r2)
}
