package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) handleSessionSQL(w http.ResponseWriter, r *http.Request) {
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
	if row.Protocol != "postgres" && row.Protocol != "mysql" {
		writeErr(w, http.StatusBadRequest, "not a db session")
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
	dbName := dbproxy.ResolveDatabase(row.Protocol, row.DatabaseName, creds.Asset.DatabaseName)
	creds.Asset.DatabaseName = dbName
	var ephRole string
	if s.dbEph != nil {
		ephCreds, info, eerr := s.dbEph.Ensure(r.Context(), id, creds, row.DBPrivilege)
		if eerr != nil {
			writeErr(w, http.StatusBadRequest, "ephemeral role: "+eerr.Error())
			return
		}
		creds = ephCreds
		creds.Asset.DatabaseName = dbName
		ephRole = info.RoleName
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	rec, err := dbproxy.NewRecorder(row.RecordingPath)
	if err != nil {
		_ = conn.WriteJSON(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	defer rec.Close()

	_ = s.sessionsvc.MarkActive(r.Context(), id)
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
		"protocol": row.Protocol, "via": "sql-ws", "asset": creds.Asset.Name, "ephemeral_role": ephRole,
	})

	bypass := rbac.HasPermission(authSess.Permissions, "users.write")
	var sqlPack policy.SQLPack
	hasSQLPack := false
	if row.SQLPolicyPackID != nil {
		if p, err := s.policy.GetSQLPack(r.Context(), *row.SQLPolicyPackID); err == nil {
			sqlPack, hasSQLPack = p, true
		}
	}
	if !hasSQLPack {
		sqlPack, hasSQLPack = s.resolveSQLPack(r.Context(), authSess.UserID, row.AssetID, authSess.Roles, bypass, row.TicketID)
	}

	_ = conn.WriteJSON(map[string]any{
		"type": "ready", "protocol": row.Protocol,
		"ephemeral_role": ephRole, "db_privilege": row.DBPrivilege,
		"database_name": dbName,
		"sql_jea":       hasSQLPack,
		"sql_jea_pack":  sqlPack.Name,
	})

	unregister := s.live.Register(id, func() { _ = conn.Close() })
	defer unregister()
	hbStop := make(chan struct{})
	defer close(hbStop)
	go sessionsvc.Heartbeat(r.Context(), s.sessionsvc, id, 30*time.Second, hbStop)

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var msg struct {
			Type      string `json:"type"`
			Statement string `json:"statement"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			_ = conn.WriteJSON(map[string]any{"type": "error", "error": "invalid json"})
			continue
		}
		switch msg.Type {
		case "ping":
			_ = conn.WriteJSON(map[string]any{"type": "pong"})
		case "query":
			ok, reason := policy.AllowSQL(sqlPack, hasSQLPack, msg.Statement)
			if !ok {
				s.denySQLClient(r, conn.WriteJSON, authSess.UserID, id, msg.Statement, reason, sqlPack.Name)
				continue
			}
			if ev, err := s.policy.CheckOpRisk(r.Context(), policy.AccessCheck{
				UserID: authSess.UserID, AssetID: row.AssetID, RoleNames: authSess.Roles,
				Bypass: bypass, TicketID: row.TicketID, ClientIP: s.clientIP(r),
				Operation: policy.SQLOperation(msg.Statement), Snapshot: row.PolicySnapshot,
				StepUpVerified: s.auth != nil && s.auth.HasOpStepUp(r.Context(), id, authSess.UserID),
			}); err == nil && !ev.OK {
				if ev.NeedsStepUp() {
					pending, aerr := s.armOpStepUp(r.Context(), authSess.UserID, authSess.Username, row.AssetID, id, ev)
					if aerr != nil {
						s.denySQLClient(r, conn.WriteJSON, authSess.UserID, id, msg.Statement, "step-up MFA required but MFA is not enrolled", sqlPack.Name)
						continue
					}
					_ = s.audit.Record(r.Context(), &authSess.UserID, "access.stepup.challenged", "asset", row.AssetID.String(), s.clientIP(r), r.UserAgent(), map[string]any{
						"code": "mfa_required", "operation": ev.Operation, "risk_score": ev.RiskScore, "max_risk": ev.MaxRisk,
					})
					fields := stepUpFields(pending, ev)
					fields["type"] = "mfa_required"
					fields["error"] = ev.RiskDenyMessage()
					_ = conn.WriteJSON(fields)
					continue
				}
				reason := ev.DenyMessage()
				s.denySQLClient(r, conn.WriteJSON, authSess.UserID, id, msg.Statement, reason, sqlPack.Name)
				_ = s.sessionsvc.AddEvent(r.Context(), id, "risk", map[string]any{
					"statement": truncateStr(msg.Statement, 8000), "reason": reason,
					"operation": ev.Operation, "risk_score": ev.RiskScore, "max_risk": ev.MaxRisk,
				})
				continue
			}
			maxRows := policy.SQLRowLimit(sqlPack, hasSQLPack)
			dlpDeny := policy.SQLDLPDeny(sqlPack, hasSQLPack)
			res, qerr := dbproxy.DialAndQuery(r.Context(), creds, msg.Statement, maxRows, dlpDeny)
			if qerr != nil && errors.Is(qerr, dbproxy.ErrDLPRowLimit) {
				reason := qerr.Error()
				denied := map[string]any{
					"statement": truncateStr(msg.Statement, 8000), "reason": reason, "pack": sqlPack.Name, "denied": true,
				}
				_ = s.sessionsvc.AddEvent(r.Context(), id, "sql_denied", denied)
				s.live.FanoutSQL(r.Context(), id, denied)
				_ = s.audit.Record(r.Context(), &authSess.UserID, "session.sql.denied", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
					"statement": truncateStr(msg.Statement, 2000), "reason": reason, "pack": sqlPack.Name,
				})
				_ = conn.WriteJSON(map[string]any{"type": "error", "error": reason, "duration_ms": res.Duration})
				continue
			}
			errMsg := ""
			if qerr != nil {
				errMsg = qerr.Error()
			} else if hasSQLPack {
				res.Columns, res.Rows = policy.MaskSQLResult(sqlPack, res.Columns, res.Rows)
			}
			rec.Record(msg.Statement, res.Duration, res.RowCount, errMsg)
			sqlEv := map[string]any{
				"statement": truncateStr(msg.Statement, 8000), "duration_ms": res.Duration,
				"row_count": res.RowCount, "error": errMsg, "via": "sql-ws", "truncated": res.Truncated,
			}
			_ = s.sessionsvc.AddEvent(r.Context(), id, "sql", sqlEv)
			s.live.FanoutSQL(r.Context(), id, sqlEv)
			_ = s.audit.Record(r.Context(), &authSess.UserID, "session.sql", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
				"statement": truncateStr(msg.Statement, 2000), "error": errMsg, "row_count": res.RowCount,
			})
			if qerr != nil {
				_ = conn.WriteJSON(map[string]any{"type": "error", "error": errMsg, "duration_ms": res.Duration})
			} else {
				_ = conn.WriteJSON(map[string]any{
					"type": "result", "columns": res.Columns, "rows": res.Rows,
					"row_count": res.RowCount, "duration_ms": res.Duration, "truncated": res.Truncated,
				})
			}
		default:
			_ = conn.WriteJSON(map[string]any{"type": "error", "error": "unknown type"})
		}
	}
	_ = s.sessionsvc.MarkEnded(r.Context(), id, "")
}

func (s *Server) denySQLClient(r *http.Request, writeJSON func(v any) error, userID, sessionID uuid.UUID, stmt, reason, pack string) {
	denied := map[string]any{
		"statement": truncateStr(stmt, 8000), "reason": reason, "pack": pack, "denied": true,
	}
	_ = s.sessionsvc.AddEvent(r.Context(), sessionID, "sql_denied", denied)
	s.live.FanoutSQL(r.Context(), sessionID, denied)
	_ = s.audit.Record(r.Context(), &userID, "session.sql.denied", "session", sessionID.String(), s.clientIP(r), r.UserAgent(), map[string]any{
		"statement": truncateStr(stmt, 2000), "reason": reason, "pack": pack,
	})
	_ = writeJSON(map[string]any{"type": "error", "error": reason})
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
