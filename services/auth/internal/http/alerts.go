package httpapi

import (
	"crypto/subtle"
	"io"
	"net/http"
	"strings"

	"github.com/keeppam/auth/internal/obs"
)

func (s *Server) handleAlertWebhook(w http.ResponseWriter, r *http.Request) {
	want := strings.TrimSpace(s.cfg.AlertWebhookToken)
	if want == "" {
		writeErr(w, http.StatusServiceUnavailable, "alert webhook disabled")
		return
	}
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("X-Alert-Token"))
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	evs, err := obs.ParseAlertmanagerWebhook(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		s.notify.OnAlertmanager(r.Context(), evs)
	}
	for _, ev := range evs {
		_ = s.audit.Record(r.Context(), nil, "obs.alert", "alert", ev.Fingerprint, s.clientIP(r), "alertmanager", map[string]any{
			"status": ev.Status, "alertname": ev.Name, "severity": ev.Severity,
			"summary": ev.Summary,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "alerts": len(evs)})
}
