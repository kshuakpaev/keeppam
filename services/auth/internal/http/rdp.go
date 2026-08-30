package httpapi

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/rdpgw"
)

func (s *Server) handleDownloadRDP(w http.ResponseWriter, r *http.Request) {
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
	if row.UserID != sess.UserID && !rbac.HasPermission(sess.Permissions, "sessions.read") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "rdp" {
		writeErr(w, http.StatusBadRequest, "not an rdp session")
		return
	}
	if row.IsWaitingSupervisor() {
		writeErr(w, http.StatusConflict, "waiting for supervisor")
		return
	}
	if s.rdp == nil || !s.rdp.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "native RDP disabled")
		return
	}
	rdp := policy.RDPRedir{}
	if row.PolicySnapshot != nil {
		rdp = row.PolicySnapshot.RDP()
	}
	if !s.rdp.NativeAllowed(row.PolicySnapshot) {
		writeErr(w, http.StatusForbidden, "rdp_native not enabled in policy")
		return
	}
	port := s.rdp.PortOf(id)
	if port == 0 && s.rdp.ProxyAvailable() {
		if _, err := s.rdp.Prepare(r.Context(), row, row.PolicySnapshot, s.cfg.SessionTTL); err == nil {
			port = s.rdp.PortOf(id)
		}
	}
	body := rdpgw.BuildRDPFile(s.rdp.PublicHost, port, row.ID.String(), rdp, row.RDPWidth, row.RDPHeight)
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="keeppam-%s.rdp"`, id.String()[:8]))
	_, _ = w.Write([]byte(body))
}
