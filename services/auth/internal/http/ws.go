package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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
	"github.com/keeppam/auth/internal/sshcmd"
	"github.com/keeppam/auth/internal/sshproxy"
	"github.com/keeppam/auth/internal/termcharset"
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
		StepUpToken string `json:"step_up_token"`
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
		creds.Asset.Protocol != "postgres" && creds.Asset.Protocol != "mysql" && creds.Asset.Protocol != "mssql" && creds.Asset.Protocol != "https" &&
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
		TicketID: body.TicketID, Reason: body.Reason, ClientIP: s.clientIP(r),
		StepUpVerified: s.consumeStepUp(r, sess.UserID, assetID, body.StepUpToken),
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
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.admin_bypass", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), map[string]any{
			"severity": "high", "ticket_id": body.TicketID, "reason": body.Reason,
		})
		ok = true
	}
	if !ok && ev.NeedsStepUp() {
		s.writeStepUpChallenge(w, r, sess, ev, assetID, uuid.Nil)
		return
	}
	if !ok {
		payload := map[string]any{"reason": "policy", "ticket_id": body.TicketID}
		ev.FillDenyPayload(payload)
		msg := ev.DenyMessage()
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.denied", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), payload)
		writeErr(w, http.StatusForbidden, msg)
		return
	}
	if s.itsm != nil && !usedBreakGlass && !bypassAdmin {
		if err := s.itsm.Enforce(r.Context(), "connect", body.TicketID); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	var sqlPackID, httpPackID, appPackID *uuid.UUID
	var k8sNS []string
	if dbproxy.IsSQLProtocol(creds.Asset.Protocol) {
		if ev.OK && ev.SQLPolicyPackID != nil {
			sqlPackID = ev.SQLPolicyPackID
		}
	}
	if (creds.Asset.Protocol == "https" || creds.Asset.Protocol == "kubectl") && ev.OK {
		if ev.HTTPPolicyPackID != nil {
			httpPackID = ev.HTTPPolicyPackID
		}
		if ev.AppObjectPackID != nil {
			appPackID = ev.AppObjectPackID
		}
	}
	if creds.Asset.Protocol == "kubectl" && ev.OK {
		k8sNS = ev.AllowedNamespaces
	}
	labels := sessionsvc.MergeLabels()
	if ut, err := s.policy.UserTags(r.Context(), sess.UserID); err == nil {
		labels = sessionsvc.MergeLabels(labels, ut)
	}
	if at, err := s.policy.AssetTags(r.Context(), assetID); err == nil {
		labels = sessionsvc.MergeLabels(labels, at)
	}
	snap := s.policy.Freeze(r.Context(), ev, usedBreakGlass, bypassAdmin)
	snap.TerminalCharset = termcharset.Normalize(creds.Asset.TerminalCharset)
	created, err := s.sessionsvc.Create(r.Context(), sess.UserID, sessionsvc.CreateInput{
		AssetID: assetID, AccountID: accountID, Protocol: creds.Asset.Protocol, ClientIP: s.clientIP(r),
		TicketID: body.TicketID, Reason: body.Reason, DBPrivilege: body.DBPrivilege,
		DatabaseName: creds.Asset.DatabaseName, SQLPolicyPackID: sqlPackID, HTTPPolicyPackID: httpPackID, AppObjectPackID: appPackID, K8sNamespaces: k8sNS,
		Isolated: httpsIsolated, BreakGlass: usedBreakGlass,
		RiskScore: ev.RiskScore, RiskFactors: ev.RiskFactors, Labels: labels,
		AccessPolicyID: ev.AccessPolicyID, ClientCountry: s.policy.ClientCountry(s.clientIP(r)),
		PolicySnapshot: snapPtr(snap),
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
		"require_supervisor": created.RequireSupervisor, "waiting_supervisor": created.WaitingSupervisor,
		"supervisor_group_id": created.SupervisorGroupID, "supervisor_group_name": created.SupervisorGroupName,
	}
	if created.WaitingSupervisor && s.notify != nil {
		s.notify.OnSupervisorWait(r.Context(), created)
	}
	if !created.WaitingSupervisor && dbproxy.IsSQLProtocol(created.Protocol) {
		tok, err := dbproxy.IssueWireToken(r.Context(), s.sessions.Redis(), created.ID, s.cfg.SessionTTL)
		if err == nil {
			out["wire_token"] = tok
			switch created.Protocol {
			case "postgres":
				out["wire_addr"] = s.cfg.PostgresWireAddr
			case "mysql":
				out["wire_addr"] = s.cfg.MySQLWireAddr
			default:
				out["wire_addr"] = s.cfg.MSSQLWireAddr
			}
			out["wire_user"] = created.ID.String()
			dbHint := created.DatabaseName
			if dbHint == "" {
				dbHint = "(default)"
			}
			out["wire_hint"] = fmt.Sprintf("user=session UUID, password=wire_token, dbname=%s, host=PAM, port from wire_addr", dbHint)
		}
	}
	if created.Protocol == "kubectl" && !created.WaitingSupervisor {
		if kube, addr, tok, err := s.issueK8sKubeconfig(r.Context(), created.ID); err == nil {
			out["kubeconfig"] = kube
			out["k8s_addr"] = addr
			out["k8s_token"] = tok
			out["wire_hint"] = fmt.Sprintf("export KUBECONFIG=./keeppam-%s.yaml && kubectl get ns", created.ID.String()[:8])
		}
	}
	if created.Protocol == "rdp" && !created.WaitingSupervisor && s.rdp != nil && s.rdp.Enabled() {
		info, err := s.rdp.Prepare(r.Context(), created, created.PolicySnapshot, s.cfg.SessionTTL)
		if err == nil && info != nil {
			out["rdp_token"] = info.Token
			out["rdp_addr"] = info.Addr
			out["rdp_port"] = info.Port
			out["rdp_user"] = info.User
			out["rdp_hint"] = info.Hint
			out["rdp_file"] = info.File
			out["rdp_proxy"] = info.ProxyOK
			out["rdp_filename"] = info.Filename
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleSearchSessionEvents(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	f := sessionsvc.EventSearchFilter{
		Q:        r.URL.Query().Get("q"),
		Type:     r.URL.Query().Get("type"),
		Filename: r.URL.Query().Get("filename"),
		Protocol: r.URL.Query().Get("protocol"),
		ClientIP: r.URL.Query().Get("client_ip"),
		Hours:    168,
		Limit:    50,
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

func (s *Server) handleSessionTimeline(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	q := r.URL.Query()
	f := sessionsvc.TimelineFilter{
		Q:        q.Get("q"),
		Filename: q.Get("filename"),
		Source:   q.Get("source"),
		Limit:    50,
	}
	if v := q.Get("limit"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := parseInt(v); err == nil {
			f.Offset = n
		}
	}
	hours := 24
	if v := q.Get("hours"); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			hours = n
		}
	}
	if hours > 2160 {
		hours = 2160
	}
	now := time.Now().UTC()
	f.To = now
	f.From = now.Add(-time.Duration(hours) * time.Hour)
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t.UTC()
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t.UTC()
		}
	}
	want := strings.TrimSpace(q.Get("user_id"))
	if want == "" {
		want = strings.TrimSpace(q.Get("username"))
	}
	canAny := rbac.HasPermission(sess.Permissions, "users.write") || rbac.HasPermission(sess.Permissions, "audit.read")
	if want == "" {
		f.UserID = sess.UserID
	} else {
		id, _, err := s.sessionsvc.LookupUser(r.Context(), want)
		if err != nil {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		if !canAny && id != sess.UserID {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		f.UserID = id
	}
	res, err := s.sessionsvc.Timeline(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if strings.EqualFold(q.Get("format"), "csv") {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="keeppam-timeline.csv"`)
		if err := sessionsvc.WriteTimelineCSV(w, res); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
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
	// Admin/auditor see all; supervisors see waiting four-eyes queue; others see own.
	if r.URL.Query().Get("waiting_supervisor") == "1" && rbac.HasPermission(sess.Permissions, "sessions.supervise") {
		f.WaitingSupervisor = true
	} else if !(rbac.HasPermission(sess.Permissions, "users.write") || rbac.HasPermission(sess.Permissions, "audit.read")) {
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
	if s.rejectIfWaitingSupervisor(w, row) {
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
	if row.UserID != sess.UserID &&
		!rbac.HasPermission(sess.Permissions, "users.write") &&
		!rbac.HasPermission(sess.Permissions, "audit.read") &&
		!rbac.HasPermission(sess.Permissions, "sessions.supervise") {
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
	if s.rdp != nil {
		s.rdp.Stop(id)
	}
	if err := s.sessionsvc.MarkEnded(r.Context(), id, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "session.ended", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"via": "api", "forced": true})
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
	} else if row.Protocol == "postgres" || row.Protocol == "mysql" || row.Protocol == "mssql" || row.Protocol == "https" || row.Protocol == "kubectl" {
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
	return rbac.HasPermission(perms, "users.write") || rbac.HasPermission(perms, "audit.read") ||
		rbac.HasPermission(perms, "sessions.supervise")
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
	if s.rejectIfWaitingSupervisor(w, row) {
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
	if row.PolicySnapshot != nil {
		rec.SetCharset(row.PolicySnapshot.TerminalCharset)
	} else {
		rec.SetCharset(creds.Asset.TerminalCharset)
	}

	client, err := s.assets.DialSSH(r.Context(), creds)
	if err != nil {
		_ = rec.Close()
		_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		_ = s.audit.Record(r.Context(), &authSess.UserID, "session.failed", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"error": err.Error()})
		return
	}

	bypass := rbac.HasPermission(authSess.Permissions, "users.write")
	var injectMu sync.Mutex
	opts := sshcmd.Deps{Policy: s.policy, Ops: s.ops, Sessions: s.sessionsvc, Audit: s.audit}.BuildOpts(r.Context(), sshcmd.Meta{
		UserID: authSess.UserID, AssetID: row.AssetID, SessionID: id,
		Username: authSess.Username, AssetName: row.AssetName, IP: s.clientIP(r),
		Roles: authSess.Roles, Bypass: bypass, BreakGlass: row.BreakGlass,
		TicketID: row.TicketID, Snap: row.PolicySnapshot,
		Inject: func(p []byte) {
			injectMu.Lock()
			defer injectMu.Unlock()
			_ = conn.WriteMessage(websocket.BinaryMessage, p)
		},
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
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
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
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.ended", "session", id.String(), s.clientIP(r), r.UserAgent(), nil)
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

func snapPtr(sn policy.Snapshot) *policy.Snapshot {
	return &sn
}
