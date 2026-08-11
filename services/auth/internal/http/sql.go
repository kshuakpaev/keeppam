package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/dbproxy"
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
	var ephRole string
	if s.dbEph != nil {
		ephCreds, info, eerr := s.dbEph.Ensure(r.Context(), id, creds, row.DBPrivilege)
		if eerr != nil {
			writeErr(w, http.StatusBadRequest, "ephemeral role: "+eerr.Error())
			return
		}
		creds = ephCreds
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
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{
		"protocol": row.Protocol, "via": "sql-ws", "asset": creds.Asset.Name, "ephemeral_role": ephRole,
	})
	_ = conn.WriteJSON(map[string]any{
		"type": "ready", "protocol": row.Protocol,
		"ephemeral_role": ephRole, "db_privilege": row.DBPrivilege,
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
			res, qerr := dbproxy.DialAndQuery(r.Context(), creds, msg.Statement)
			errMsg := ""
			if qerr != nil {
				errMsg = qerr.Error()
			}
			rec.Record(msg.Statement, res.Duration, res.RowCount, errMsg)
			_ = s.sessionsvc.AddEvent(r.Context(), id, "sql", map[string]any{
				"statement": truncateStr(msg.Statement, 8000), "duration_ms": res.Duration,
				"row_count": res.RowCount, "error": errMsg, "via": "sql-ws",
			})
			_ = s.audit.Record(r.Context(), &authSess.UserID, "session.sql", "session", id.String(), clientIP(r), r.UserAgent(), map[string]any{
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

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
