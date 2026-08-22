package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/citrix/hdx"
	"github.com/keeppam/auth/internal/sessionsvc"
)

type hdxSink struct{ s *sessionsvc.Service }

func (h hdxSink) GetRecordingPath(ctx context.Context, sessionID uuid.UUID) (string, time.Time, error) {
	row, err := h.s.Get(ctx, sessionID)
	if err != nil {
		return "", time.Time{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	return row.RecordingPath, base, nil
}

func (h hdxSink) AddEventAt(ctx context.Context, sessionID uuid.UUID, ts time.Time, eventType string, payload map[string]any) error {
	return h.s.AddEventAt(ctx, sessionID, ts, eventType, payload)
}

func (s *Server) handleCitrixHDXHealth(w http.ResponseWriter, r *http.Request) {
	if s.hdx == nil || !s.hdx.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"status":     "disabled",
			"hint":       "set KEEPPAM_CITRIX_HDX_PLUGIN_URL and asset citrix_transport=hdx",
		})
		return
	}
	h, err := s.hdx.Health(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true, "status": "unreachable", "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true, "status": h.Status, "capabilities": h.Capabilities,
		"vendor": h.Vendor, "version": h.Version, "plugin_url": s.cfg.CitrixHDXPluginURL,
		"callback_base": s.hdxCallbackBase(),
	})
}

// Plugin → KeepPAM recording ingest (Bearer ingest token from Start).
func (s *Server) handleCitrixHDXIngest(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "missing ingest token")
		return
	}
	sid, err := hdx.LookupByToken(r.Context(), s.sessions.Redis(), tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid ingest token")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	var req hdx.IngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	n, err := s.applyHDXEvents(r.Context(), sid, req.Events)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": n, "session_id": sid})
}

func (s *Server) handleCitrixHDXSync(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.syncHDXFromPlugin(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"synced": n, "session_id": id})
}

func (s *Server) hdxCallbackBase() string {
	base := strings.TrimSpace(s.cfg.CitrixHDXCallbackBase)
	if base == "" {
		base = strings.TrimSpace(s.cfg.CORSOrigin)
	}
	return strings.TrimRight(base, "/")
}

func (s *Server) applyHDXEvents(ctx context.Context, sessionID uuid.UUID, events []hdx.RecordingEvt) (int, error) {
	recPath, base, err := hdxSink{s.sessionsvc}.GetRecordingPath(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	return hdx.ApplyEvents(ctx, s.sessions.Redis(), hdxSink{s.sessionsvc}, sessionID, recPath, base, events, s.cfg.SessionTTL)
}

func (s *Server) syncHDXFromPlugin(ctx context.Context, sessionID uuid.UUID) (int, error) {
	if s.hdx == nil || !s.hdx.Enabled() {
		return 0, nil
	}
	b, err := hdx.GetBinding(ctx, s.sessions.Redis(), sessionID)
	if err != nil {
		return 0, err
	}
	st, err := s.hdx.Status(ctx, b.PluginSessionID)
	if err != nil {
		return 0, err
	}
	return s.applyHDXEvents(ctx, sessionID, st.Events)
}

func (s *Server) stopHDXSession(ctx context.Context, sessionID uuid.UUID) {
	hdx.Finalize(ctx, s.sessions.Redis(), s.hdx, hdxSink{s.sessionsvc}, sessionID, s.cfg.SessionTTL)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-KeepPAM-HDX-Token"))
}
