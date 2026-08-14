package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/sshproxy"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin: func(r *http.Request) bool {
		return true // CORS origin enforced at app layer; nginx same-origin in prod
	},
}

type wsClientMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var body struct {
		AssetID     string `json:"asset_id"`
		AccountID   string `json:"account_id"`
		TicketID    string `json:"ticket_id"`
		Reason      string `json:"reason"`
		DBPrivilege string `json:"db_privilege"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	assetID, err := uuid.Parse(body.AssetID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid asset_id")
		return
	}
	accountID, err := uuid.Parse(body.AccountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account_id")
		return
	}
	creds, err := s.assets.GetTargetCreds(r.Context(), assetID, accountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if creds.Asset.Protocol != "ssh" && creds.Asset.Protocol != "rdp" && creds.Asset.Protocol != "vnc" &&
		creds.Asset.Protocol != "postgres" && creds.Asset.Protocol != "mysql" && creds.Asset.Protocol != "https" &&
		creds.Asset.Protocol != "kubectl" {
		writeErr(w, http.StatusBadRequest, "unsupported protocol")
		return
	}
	httpsIsolated := creds.Asset.Protocol == "https" && s.apps != nil && s.apps.IsIsolated(r.Context(), assetID)
	if creds.Asset.Protocol == "https" && s.apps != nil && !s.apps.NeedsHTTPSSession(r.Context(), assetID) {
		writeErr(w, http.StatusBadRequest, "https sessions require app recording_mode=full or isolated; use app access lease otherwise")
		return
	}
	bypassAdmin := rbac.HasPermission(sess.Permissions, "users.write")
	check := policy.AccessCheck{
		UserID: sess.UserID, AssetID: assetID, RoleNames: sess.Roles, Bypass: false, Now: time.Now(),
		TicketID: body.TicketID, Reason: body.Reason, ClientIP: clientIP(r),
	}
	ev, err := s.policy.Evaluate(r.Context(), check)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok := ev.OK
	usedBreakGlass := false
	if !ok {
		if bg, berr := s.policy.HasActiveBreakGlass(r.Context(), sess.UserID, assetID); berr == nil && bg {
			ok = true
			usedBreakGlass = true
		}
	}
	if !ok && bypassAdmin {
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.admin_bypass", "asset", assetID.String(), clientIP(r), r.UserAgent(), map[string]any{
			"severity": "high", "ticket_id": body.TicketID, "reason": body.Reason,
		})
		ok = true
	}
	if !ok {
		payload := map[string]any{"reason": "policy", "ticket_id": body.TicketID}
		msg := "access denied by policy"
		if ev.DeniedByRisk {
			payload["reason"] = "risk"
			payload["risk_score"] = ev.RiskScore
			payload["risk_factors"] = ev.RiskFactors
			payload["max_risk"] = ev.MaxRisk
			payload["risk_action"] = ev.RiskAction
			msg = ev.DenyMessage()
		}
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.denied", "asset", assetID.String(), clientIP(r), r.UserAgent(), payload)
		writeErr(w, http.StatusForbidden, msg)
		return
	}
	if s.itsm != nil && !usedBreakGlass && !bypassAdmin {
		if err := s.itsm.Enforce(r.Context(), "connect", body.TicketID); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	var sqlPackID *uuid.UUID
	var k8sNS []string
	if creds.Asset.Protocol == "postgres" || creds.Asset.Protocol == "mysql" {
		if ev.OK && ev.SQLPolicyPackID != nil {
			sqlPackID = ev.SQLPolicyPackID
		}
	}
	if creds.Asset.Protocol == "kubectl" && ev.OK {
		k8sNS = ev.AllowedNamespaces
	}
	created, err := s.sessionsvc.Create(r.Context(), sess.UserID, sessionsvc.CreateInput{
		AssetID: assetID, AccountID: accountID, Protocol: creds.Asset.Protocol, ClientIP: clientIP(r),
		TicketID: body.TicketID, Reason: body.Reason, DBPrivilege: body.DBPrivilege,
		DatabaseName: creds.Asset.DatabaseName, SQLPolicyPackID: sqlPackID, K8sNamespaces: k8sNS,
		Isolated: httpsIsolated, BreakGlass: usedBreakGlass,
	}, r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"id": created.ID, "user_id": created.UserID, "asset_id": created.AssetID, "account_id": created.AccountID,
		"protocol": created.Protocol, "status": created.Status, "client_ip": created.ClientIP,
		"recording_path": created.RecordingPath, "created_at": created.CreatedAt,
		"has_recording": created.HasRecording, "ticket_id": created.TicketID, "reason": created.Reason,
		"db_privilege": created.DBPrivilege, "database_name": created.DatabaseName, "isolated": created.Isolated,
		"break_glass": created.BreakGlass, "k8s_namespaces": created.K8sNamespaces,
	}
	if created.Protocol == "postgres" || created.Protocol == "mysql" {
		tok, err := dbproxy.IssueWireToken(r.Context(), s.sessions.Redis(), created.ID, s.cfg.SessionTTL)
		if err == nil {
			out["wire_token"] = tok
			if created.Protocol == "postgres" {
				out["wire_addr"] = s.cfg.PostgresWireAddr
			} else {
				out["wire_addr"] = s.cfg.MySQLWireAddr
			}
			out["wire_user"] = created.ID.String()
			dbHint := created.DatabaseName
			if dbHint == "" {
				dbHint = "(default)"
			}
			out["wire_hint"] = fmt.Sprintf("user=session UUID, password=wire_token, dbname=%s, host=PAM, port from wire_addr", dbHint)
		}
	}
	if created.Protocol == "kubectl" {
		if kube, addr, tok, err := s.issueK8sKubeconfig(r.Context(), created.ID); err == nil {
			out["kubeconfig"] = kube
			out["k8s_addr"] = addr
			out["k8s_token"] = tok
			out["wire_hint"] = fmt.Sprintf("export KUBECONFIG=./keeppam-%s.yaml && kubectl get ns", created.ID.String()[:8])
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleSearchSessionEvents(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	f := sessionsvc.EventSearchFilter{
		Q:     r.URL.Query().Get("q"),
		Type:  r.URL.Query().Get("type"),
		Hours: 168,
		Limit: 50,
	}
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Hours = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Offset = n
		}
	}
	if !(rbac.HasPermission(sess.Permissions, "users.write") || rbac.HasPermission(sess.Permissions, "audit.read")) {
		f.OnlyUser = &sess.UserID
	}
	list, total, err := s.sessionsvc.SearchEvents(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": list, "total": total})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	f := sessionsvc.ListFilter{
		Status:   r.URL.Query().Get("status"),
		Protocol: r.URL.Query().Get("protocol"),
		Q:        r.URL.Query().Get("q"),
		Limit:    50,
		Offset:   0,
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Offset = n
		}
	}
	// Admin/auditor see all; others (operator) see own.
	if !(rbac.HasPermission(sess.Permissions, "users.write") || rbac.HasPermission(sess.Permissions, "audit.read")) {
		f.OnlyUser = &sess.UserID
	}
	list, total, err := s.sessionsvc.List(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list, "total": total})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		if sessionsvc.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !canViewSession(sess.Permissions, sess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (s *Server) handleGetKubeconfig(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
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
	if row.Protocol != "kubectl" {
		writeErr(w, http.StatusBadRequest, "not a kubectl session")
		return
	}
	if sess.UserID != row.UserID && !rbac.HasPermission(sess.Permissions, "users.write") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusGone, "session ended")
		return
	}
	kube, addr, tok, err := s.issueK8sKubeconfig(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.sessionsvc.Touch(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{
		"kubeconfig": kube, "k8s_addr": addr, "k8s_token": tok,
	})
}

func (s *Server) issueK8sKubeconfig(ctx context.Context, sessionID uuid.UUID) (kube, addr, bearer string, err error) {
	tok, err := k8sproxy.GetToken(ctx, s.sessions.Redis(), sessionID)
	if err != nil || tok == "" {
		tok, err = k8sproxy.IssueToken(ctx, s.sessions.Redis(), sessionID, s.cfg.SessionTTL)
		if err != nil {
			return "", "", "", err
		}
	}
	addr = s.cfg.K8sPublicURL
	if addr == "" {
		addr = k8sproxy.DefaultPublicURL(s.cfg.CORSOrigin, s.cfg.K8sAPIAddr)
	}
	bearer = k8sproxy.BearerValue(sessionID, tok)
	return k8sproxy.RenderKubeconfig(addr, bearer), addr, bearer, nil
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
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
	if !canViewSession(sess.Permissions, sess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.UserID == sess.UserID && !rbac.HasPermission(sess.Permissions, "sessions.connect") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Status == "ended" || row.Status == "failed" {
		writeJSON(w, http.StatusOK, row)
		return
	}
	if s.live != nil {
		s.live.Kill(r.Context(), id)
	}
	if err := s.sessionsvc.MarkEnded(r.Context(), id, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "session.ended", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{"via": "api", "forced": true})
	row, _ = s.sessionsvc.Get(r.Context(), id)
	writeJSON(w, http.StatusOK, row)
}

func (s *Server) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
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
	if !canViewSession(sess.Permissions, sess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	path, err := s.sessionsvc.RecordingFile(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if row.Protocol == "rdp" || row.Protocol == "vnc" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", id.String()+".guac"))
	} else if row.Protocol == "postgres" || row.Protocol == "mysql" || row.Protocol == "https" || row.Protocol == "kubectl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id.String()+".jsonl"))
	} else {
		w.Header().Set("Content-Type", "application/x-asciicast")
	}
	http.ServeFile(w, r, path)
}

func canViewSession(perms []string, viewer, owner uuid.UUID) bool {
	if viewer == owner {
		return true
	}
	return rbac.HasPermission(perms, "users.write") || rbac.HasPermission(perms, "audit.read")
}

func (s *Server) handleSessionWS(w http.ResponseWriter, r *http.Request) {
	// Cookie session auth (WS handshake includes cookies).
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
	r = s.bindSession(r, authSess)
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
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusBadRequest, "session not startable")
		return
	}

	creds, err := s.assets.GetTargetCreds(r.Context(), row.AssetID, row.AccountID)
	if err != nil {
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	cols, rows := 120, 40
	if v := r.URL.Query().Get("cols"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			cols = n
		}
	}
	if v := r.URL.Query().Get("rows"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			rows = n
		}
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws upgrade", "err", err)
		return
	}
	defer conn.Close()

	rec, err := sshproxy.NewRecorder(row.RecordingPath, cols, rows, creds.Asset.Name)
	if err != nil {
		_ = writeWSJSON(conn, map[string]string{"type": "error", "message": "recorder failed: " + err.Error()})
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		return
	}

	client, err := s.assets.DialSSH(r.Context(), creds)
	if err != nil {
		_ = rec.Close()
		_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		_ = s.audit.Record(r.Context(), &authSess.UserID, "session.failed", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{"error": err.Error()})
		return
	}

	bypass := rbac.HasPermission(authSess.Permissions, "users.write")
	var injectMu sync.Mutex
	opts := s.buildSSHSessionOpts(r.Context(), authSess.UserID, row.AssetID, id, authSess.Roles, bypass, row.TicketID, func(p []byte) {
		injectMu.Lock()
		defer injectMu.Unlock()
		_ = conn.WriteMessage(websocket.BinaryMessage, p)
	})
	bridge, err := sshproxy.StartSessionWith(client, cols, rows, rec, opts)
	if err != nil {
		_ = client.Close()
		_ = rec.Close()
		_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		return
	}
	defer bridge.Close()

	_ = s.sessionsvc.MarkActive(r.Context(), id)
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{
		"asset": creds.Asset.Name, "account": creds.Account.Username,
	})
	_ = writeWSJSON(conn, map[string]string{"type": "ready"})

	unregister := s.live.Register(id, func() {
		bridge.Close()
		_ = conn.Close()
	})
	defer unregister()

	hbStop := make(chan struct{})
	go sessionsvc.Heartbeat(r.Context(), s.sessionsvc, id, 30*time.Second, hbStop)
	defer close(hbStop)

	var writeMu sync.Mutex
	safeWrite := func(mt int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return conn.WriteMessage(mt, data)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = bridge.CopyOutput(writerFunc(func(p []byte) (int, error) {
			s.live.FanoutOutput(r.Context(), id, p)
			if err := safeWrite(websocket.BinaryMessage, p); err != nil {
				return 0, err
			}
			return len(p), nil
		}))
	}()

	go func() {
		<-done
		_ = safeWrite(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
	}()

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage {
			var msg wsClientMsg
			if json.Unmarshal(data, &msg) == nil {
				switch msg.Type {
				case "resize":
					if msg.Cols > 0 && msg.Rows > 0 {
						_ = bridge.Resize(msg.Cols, msg.Rows)
					}
					continue
				case "input":
					data = []byte(msg.Data)
				default:
					// treat as raw input
				}
			}
		}
		if _, err := bridge.Write(data); err != nil {
			break
		}
	}

	_ = s.sessionsvc.MarkEnded(r.Context(), id, "")
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.ended", "session", id.String(), clientIP(r), r.UserAgent(), nil)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func writeWSJSON(conn *websocket.Conn, v any) error {
	b, _ := json.Marshal(v)
	return conn.WriteMessage(websocket.TextMessage, b)
}

func parseInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
