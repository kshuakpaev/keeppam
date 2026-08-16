package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleSessionWatch(w http.ResponseWriter, r *http.Request) {
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
	if !rbac.HasPermission(authSess.Permissions, "sessions.read") {
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
	if !canViewSession(authSess.Permissions, authSess.UserID, row.UserID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusBadRequest, "session is not live")
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.watched", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
		"owner_id": row.UserID.String(), "protocol": row.Protocol, "asset": row.AssetName,
	})

	var writeMu sync.Mutex
	writeJSON := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return conn.WriteJSON(v)
	}
	writeBin := func(p []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		return conn.WriteMessage(websocket.BinaryMessage, p)
	}

	if err := writeJSON(map[string]any{
		"type": "ready", "protocol": row.Protocol, "readonly": true,
		"username": row.Username, "asset": row.AssetName, "account": row.AccountUsername,
	}); err != nil {
		return
	}

	if snap := s.live.Snapshot(r.Context(), id); len(snap) > 0 {
		if err := writeBin(snap); err != nil {
			return
		}
	}
	if evs, err := s.sessionsvc.ListEvents(r.Context(), id, 40); err == nil {
		for _, e := range evs {
			if err := writeJSON(map[string]any{"type": "event", "event_type": e.Type, "payload": e.Payload, "ts": e.TS}); err != nil {
				return
			}
		}
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	ch, unsub := s.live.Subscribe(ctx, id)
	defer unsub()

	conn.SetReadLimit(4096)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			writeMu.Lock()
			_ = conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
			writeMu.Unlock()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			switch ev.Kind {
			case "out":
				raw, err := base64.StdEncoding.DecodeString(ev.Data)
				if err != nil || len(raw) == 0 {
					continue
				}
				if err := writeBin(raw); err != nil {
					return
				}
			case "sql":
				var payload any
				if json.Unmarshal([]byte(ev.Data), &payload) != nil {
					payload = ev.Data
				}
				if err := writeJSON(map[string]any{"type": "sql", "payload": payload}); err != nil {
					return
				}
			case "end":
				_ = writeJSON(map[string]any{"type": "ended"})
				return
			case "meta":
				if err := writeJSON(map[string]any{"type": "meta", "data": ev.Data}); err != nil {
					return
				}
			}
		}
	}
}
