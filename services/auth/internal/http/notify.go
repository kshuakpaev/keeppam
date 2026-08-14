package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/notify"
)

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeJSON(w, http.StatusOK, map[string]any{"notifications": []any{}, "unread": 0})
		return
	}
	sess := mustSess(r)
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := s.notify.List(r.Context(), sess.UserID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	unread, err := s.notify.UnreadCount(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notifications": list, "unread": unread})
}

func (s *Server) handleUnreadNotifications(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeJSON(w, http.StatusOK, map[string]any{"unread": 0})
		return
	}
	sess := mustSess(r)
	n, err := s.notify.UnreadCount(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unread": n})
}

func (s *Server) handleReadNotification(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeErr(w, http.StatusServiceUnavailable, "notify unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.notify.MarkRead(r.Context(), sess.UserID, id); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadAllNotifications(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	sess := mustSess(r)
	if err := s.notify.MarkAllRead(r.Context(), sess.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetNotifySettings(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeErr(w, http.StatusServiceUnavailable, "notify unavailable")
		return
	}
	cfg, err := s.notify.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.AuthHeader = ""
	cfg.SMTPPassword = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutNotifySettings(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeErr(w, http.StatusServiceUnavailable, "notify unavailable")
		return
	}
	sess := mustSess(r)
	var in notify.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.notify.UpdateSettings(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out.AuthHeader = ""
	out.SMTPPassword = ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTestNotifyEmail(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		writeErr(w, http.StatusServiceUnavailable, "notify unavailable")
		return
	}
	sess := mustSess(r)
	if err := s.notify.SendTest(r.Context(), sess.UserID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
