package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	citrixica "github.com/keeppam/auth/internal/citrix"
	"github.com/keeppam/auth/internal/citrix/hdx"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/nac"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/rdpgw"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/sshcmd"
	"github.com/keeppam/auth/internal/sshproxy"
	"github.com/keeppam/auth/internal/telnet"
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
	if s.fenceStandbySessions(w, r) {
		return
	}
	sess := mustSess(r)
	var body struct {
		AssetID     string `json:"asset_id"`
		AccountID   string `json:"account_id"`
		TicketID    string `json:"ticket_id"`
		Reason      string `json:"reason"`
		DBPrivilege string `json:"db_privilege"`
		StepUpToken string `json:"step_up_token"`
		RDPWidth    int    `json:"rdp_width"`
		RDPHeight   int    `json:"rdp_height"`
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
	if !s.ensureAssetLicenseVisible(w, r, assetID) {
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
		creds.Asset.Protocol != "kubectl" && creds.Asset.Protocol != "telnet" && creds.Asset.Protocol != "tn3270" &&
		creds.Asset.Protocol != "citrix" {
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
		ClientDevices: s.clientDevices(r),
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
	if s.uebaml != nil {
		score, factors, mlRes, err := s.uebaml.EnhanceConnect(r.Context(), sess.UserID, assetID, ev.RiskScore, ev.RiskFactors)
		if err == nil && mlRes.AddedScore > 0 {
			ev.RiskScore = score
			ev.RiskFactors = factors
			_ = s.audit.Record(r.Context(), &sess.UserID, "ueba_ml.connect", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), map[string]any{
				"ml_score": mlRes.MLScore, "threshold": mlRes.Threshold, "peer_group": mlRes.PeerGroup,
				"peer_ratio": mlRes.PeerRatio, "added_score": mlRes.AddedScore, "factors": mlRes.AddedFactors,
			})
		}
	}
	if s.itsm != nil && !usedBreakGlass && !bypassAdmin {
		if err := s.itsm.Enforce(r.Context(), "connect", body.TicketID); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	if s.nac != nil && !usedBreakGlass && !bypassAdmin {
		nacResp, auditOnly, deny, err := s.nac.CheckPreConnect(r.Context(), nac.ConnectInput{
			UserID: sess.UserID, Username: sess.Username, AssetID: assetID,
			AssetName: creds.Asset.Name, Protocol: creds.Asset.Protocol,
			ClientIP: s.clientIP(r), ClientMAC: strings.TrimSpace(r.Header.Get("X-KeepPAM-Client-MAC")),
			ClientDevices: s.clientDevices(r),
		})
		if err != nil {
			writeErr(w, http.StatusBadGateway, "nac check failed")
			return
		}
		if auditOnly || deny {
			payload := map[string]any{
				"via": "pre_connect", "allowed": nacResp.Allowed, "audit_only": auditOnly,
			}
			if nacResp.Reason != "" {
				payload["reason"] = nacResp.Reason
			}
			if nacResp.VLAN != "" {
				payload["vlan"] = nacResp.VLAN
			}
			if nacResp.Policy != "" {
				payload["policy"] = nacResp.Policy
			}
			_ = s.audit.Record(r.Context(), &sess.UserID, "session.nac.denied", "asset", assetID.String(), s.clientIP(r), r.UserAgent(), payload)
		}
		if deny {
			writeErr(w, http.StatusForbidden, "nac posture denied: "+nacResp.Reason)
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
	rdpW, rdpH := body.RDPWidth, body.RDPHeight
	if creds.Asset.Protocol == "rdp" {
		rdpW, rdpH = rdpgw.NormalizeSize(body.RDPWidth, body.RDPHeight)
		if body.RDPWidth <= 0 || body.RDPHeight <= 0 {
			rdpW, rdpH = 0, 0
		}
	} else {
		rdpW, rdpH = 0, 0
	}
	created, err := s.sessionsvc.Create(r.Context(), sess.UserID, sessionsvc.CreateInput{
		AssetID: assetID, AccountID: accountID, Protocol: creds.Asset.Protocol, ClientIP: s.clientIP(r),
		TicketID: body.TicketID, Reason: body.Reason, DBPrivilege: body.DBPrivilege,
		DatabaseName: creds.Asset.DatabaseName, SQLPolicyPackID: sqlPackID, HTTPPolicyPackID: httpPackID, AppObjectPackID: appPackID, K8sNamespaces: k8sNS,
		Isolated: httpsIsolated, BreakGlass: usedBreakGlass,
		RiskScore: ev.RiskScore, RiskFactors: ev.RiskFactors, Labels: labels,
		AccessPolicyID: ev.AccessPolicyID, ClientCountry: s.policy.ClientCountry(s.clientIP(r)),
		PolicySnapshot: snapPtr(snap), RDPWidth: rdpW, RDPHeight: rdpH,
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
		"rdp_width": created.RDPWidth, "rdp_height": created.RDPHeight,
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
	if !created.WaitingSupervisor && created.Protocol == "telnet" && s.cfg.TelnetAddr != "" && s.cfg.TelnetAddr != "off" {
		tok, err := dbproxy.IssueWireToken(r.Context(), s.sessions.Redis(), created.ID, s.cfg.SessionTTL)
		if err == nil {
			out["wire_token"] = tok
			out["wire_addr"] = s.cfg.TelnetAddr
			out["wire_user"] = created.ID.String()
			out["wire_hint"] = "telnet PAM host (wire_addr); login=session UUID, password=wire_token"
		}
	}
	if !created.WaitingSupervisor && created.Protocol == "tn3270" && s.cfg.TN3270Addr != "" && s.cfg.TN3270Addr != "off" {
		tok, err := dbproxy.IssueWireToken(r.Context(), s.sessions.Redis(), created.ID, s.cfg.SessionTTL)
		if err == nil {
			out["wire_token"] = tok
			out["wire_addr"] = s.cfg.TN3270Addr
			out["wire_user"] = created.ID.String()
			out["wire_hint"] = "x3270/c3270 → PAM wire_addr; on KeepPAM login screen: Session UUID + wire_token"
			if cp := creds.Asset.Tn3270Codepage; cp != "" && cp != "cp037" {
				out["tn3270_codepage"] = cp
				if tt := creds.Asset.Tn3270TerminalType; tt != "" {
					out["tn3270_terminal_type"] = tt
				}
				out["wire_hint"] = out["wire_hint"].(string) + "; asset DBCS codepage=" + cp
			}
		}
	}
	if !created.WaitingSupervisor && created.Protocol == "citrix" {
		transport := creds.Asset.CitrixTransport
		if transport == "" {
			transport = "socks"
		}
		// Phase 3: OEM HDX terminate plugin
		if transport == "hdx" {
			if s.hdx == nil || !s.hdx.Enabled() {
				writeErr(w, http.StatusServiceUnavailable, "citrix_transport=hdx but KEEPPAM_CITRIX_HDX_PLUGIN_URL not set")
				return
			}
			if _, err := s.hdx.Health(r.Context()); err != nil {
				writeErr(w, http.StatusBadGateway, "hdx plugin unhealthy: "+err.Error())
				return
			}
			target := creds.Asset.Address
			if target == "" {
				target = creds.Asset.Hostname
			}
			staTicket := ""
			if sta, err := citrixica.IssueSTATicket(r.Context(), s.sessions.Redis(), created.ID, creds.Asset.ID, s.cfg.SessionTTL); err == nil {
				staTicket = sta.Ticket
				out["citrix_sta_ticket"] = sta.Ticket
				out["citrix_sta_expires_at"] = sta.ExpiresAt.UTC().Format(time.RFC3339)
			}
			ttlSec := int(s.cfg.SessionTTL.Seconds())
			if ttlSec <= 0 {
				ttlSec = 3600
			}
			// Bind first so ingest token exists before plugin Start (callback may fire immediately).
			bind, err := hdx.Bind(r.Context(), s.sessions.Redis(), created.ID, "pending", s.cfg.SessionTTL)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "hdx bind: "+err.Error())
				return
			}
			cbBase := s.hdxCallbackBase()
			st, err := s.hdx.Start(r.Context(), hdx.StartRequest{
				KeepPAMSessionID: created.ID.String(),
				VDAHost:          target,
				VDAPort:          creds.Asset.Port,
				Username:         creds.Account.Username,
				Password:         creds.Secret,
				InitialProgram:   creds.Asset.CitrixPublishedApp,
				STATicket:        staTicket,
				StoreFrontURL:    creds.Asset.CitrixStoreFrontURL,
				TTLSeconds:       ttlSec,
				RecordingHint:    created.RecordingPath,
				CallbackURL:      hdx.CallbackURL(cbBase),
				IngestToken:      bind.IngestToken,
				Record:           true,
			})
			if err != nil {
				hdx.ClearBinding(r.Context(), s.sessions.Redis(), created.ID)
				writeErr(w, http.StatusBadGateway, "hdx plugin start: "+err.Error())
				return
			}
			// Re-bind with real plugin session id (same ingest token).
			_ = hdx.SetPluginSessionID(r.Context(), s.sessions.Redis(), created.ID, st.PluginSessionID, s.cfg.SessionTTL)
			_ = hdx.AppendJSONL(created.RecordingPath, hdx.RecordingEvt{
				T: time.Now().UTC().Format(time.RFC3339Nano), Event: "hdx_started", Seq: 1,
				Meta: map[string]any{"plugin_session_id": st.PluginSessionID, "listen_addr": st.ListenAddr, "mode": st.Mode},
			})
			_ = s.sessionsvc.MarkActive(r.Context(), created.ID)
			_ = s.sessionsvc.AddEvent(r.Context(), created.ID, "citrix_hdx_started", map[string]any{
				"plugin_session_id": st.PluginSessionID, "listen_addr": st.ListenAddr, "mode": st.Mode,
				"record": true, "callback": hdx.CallbackURL(cbBase) != "",
			})
			out["citrix_transport"] = "hdx"
			out["citrix_hdx"] = map[string]any{
				"plugin_session_id": st.PluginSessionID,
				"listen_addr":       st.ListenAddr,
				"mode":              st.Mode,
				"message":           st.Message,
				"recording":         created.RecordingPath != "",
			}
			out["recording_path"] = created.RecordingPath
			out["wire_hint"] = "HDX terminate+record via OEM plugin (docs/citrix-hdx-oem.txt). Ingest → /api/v1/citrix/hdx/ingest."
			writeJSON(w, http.StatusCreated, out)
			return
		}
	}
	if !created.WaitingSupervisor && created.Protocol == "citrix" && s.cfg.CitrixSocksAddr != "" && s.cfg.CitrixSocksAddr != "off" {
		tok, err := dbproxy.IssueWireToken(r.Context(), s.sessions.Redis(), created.ID, s.cfg.SessionTTL)
		if err == nil {
			host := s.cfg.CitrixPublicHost
			if host == "" || host == "off" {
				host = "127.0.0.1"
			}
			socksPort := 1081
			if _, p, err := net.SplitHostPort(normalizeAddr(s.cfg.CitrixSocksAddr)); err == nil {
				if n, err := strconv.Atoi(p); err == nil && n > 0 {
					socksPort = n
				}
			}
			target := creds.Asset.Address
			if target == "" {
				target = creds.Asset.Hostname
			}
			ica := citrixica.BuildICAFile(citrixica.ICAFileOpts{
				ProxyHost: host, ProxyPort: socksPort,
				ProxyUser: created.ID.String(), ProxyPassword: tok,
				TargetHost: target, TargetPort: creds.Asset.Port,
				AppName: creds.Asset.Name, Title: creds.Asset.Name,
				InitialProg:   creds.Asset.CitrixPublishedApp,
				StoreFrontURL: creds.Asset.CitrixStoreFrontURL,
				Username:      creds.Account.Username,
			})
			if sta, err := citrixica.IssueSTATicket(r.Context(), s.sessions.Redis(), created.ID, creds.Asset.ID, s.cfg.SessionTTL); err == nil {
				ica = citrixica.BuildICAFile(citrixica.ICAFileOpts{
					ProxyHost: host, ProxyPort: socksPort,
					ProxyUser: created.ID.String(), ProxyPassword: tok,
					TargetHost: target, TargetPort: creds.Asset.Port,
					AppName: creds.Asset.Name, Title: creds.Asset.Name,
					InitialProg:   creds.Asset.CitrixPublishedApp,
					StoreFrontURL: creds.Asset.CitrixStoreFrontURL,
					Username:      creds.Account.Username,
					STATicket:     sta.Ticket,
				})
				out["citrix_sta_ticket"] = sta.Ticket
				out["citrix_sta_expires_at"] = sta.ExpiresAt.UTC().Format(time.RFC3339)
				_ = s.sessionsvc.AddEvent(r.Context(), created.ID, "citrix_sta_issued", map[string]any{
					"ticket_prefix": sta.Ticket[:8], "transport": creds.Asset.CitrixTransport,
				})
			}
			out["wire_token"] = tok
			out["wire_addr"] = s.cfg.CitrixSocksAddr
			out["wire_user"] = created.ID.String()
			out["citrix_ica"] = ica
			out["citrix_filename"] = fmt.Sprintf("keeppam-%s.ica", created.ID.String()[:8])
			out["citrix_transport"] = creds.Asset.CitrixTransport
			if creds.Asset.CitrixTransport == "hdx_pending" {
				out["wire_hint"] = "Workspace: .ica через SOCKS. citrix_transport=hdx_pending — HDX terminate ещё OEM (docs/citrix-hdx.txt)."
			} else {
				out["wire_hint"] = "Workspace: .ica (SOCKS). STA: KeepPAM /Scripts/CtxSta.dll или JSON /api/v1/citrix/sta/{ticket}. StoreFront enum — assets/…/citrix/resources."
			}
			out["citrix_sta_cgi"] = "/Scripts/CtxSta.dll"
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
		Process:  r.URL.Query().Get("process"),
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
		Process:  q.Get("process"),
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

	type ttyBridge interface {
		Write([]byte) (int, error)
		Resize(cols, rows int) error
		CopyOutput(dst io.Writer) error
		Close()
	}

	var bridge ttyBridge
	if creds.Asset.Protocol == "telnet" || row.Protocol == "telnet" {
		host := creds.Asset.Address
		if host == "" {
			host = creds.Asset.Hostname
		}
		up, err := telnet.Dial(r.Context(), host, creds.Asset.Port)
		if err != nil {
			_ = rec.Close()
			_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
			_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
			_ = s.audit.Record(r.Context(), &authSess.UserID, "session.failed", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"error": err.Error()})
			return
		}
		tb, err := telnet.StartBridge(up, cols, rows, rec, telnet.SessionOpts{
			Username: creds.Account.Username, Password: creds.Secret,
			InjectLogin: true, TermType: "xterm-256color",
		})
		if err != nil {
			_ = up.Close()
			_ = rec.Close()
			_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
			_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
			return
		}
		bridge = tb
	} else {
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
		sb, err := sshproxy.StartSessionWith(client, cols, rows, rec, opts)
		if err != nil {
			_ = client.Close()
			_ = rec.Close()
			_ = writeWSJSON(conn, map[string]string{"type": "error", "message": err.Error()})
			_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
			return
		}
		bridge = sb
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
	safePing := func() error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
	}

	// Keep idle SSH websockets alive through proxies/NAT (same pattern as live watch).
	const wsReadIdle = 90 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(wsReadIdle))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(wsReadIdle))
		return nil
	})
	conn.SetPingHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(wsReadIdle))
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
	})

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

	pingStop := make(chan struct{})
	defer close(pingStop)
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pingStop:
				return
			case <-done:
				return
			case <-ticker.C:
				if err := safePing(); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(wsReadIdle))
		if mt == websocket.TextMessage {
			var msg wsClientMsg
			if json.Unmarshal(data, &msg) == nil {
				switch msg.Type {
				case "ping":
					_ = safeWrite(websocket.TextMessage, []byte(`{"type":"pong"}`))
					continue
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

// normalizeAddr ensures host:port form for net.SplitHostPort (":1081" → "0.0.0.0:1081").
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if strings.HasPrefix(addr, ":") {
		return "0.0.0.0" + addr
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "1081")
	}
	return addr
}

func snapPtr(sn policy.Snapshot) *policy.Snapshot {
	return &sn
}
