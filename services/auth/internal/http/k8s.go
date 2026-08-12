package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/appaccess"
	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleK8sAccess(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		AccountID string `json:"account_id"`
		TicketID  string `json:"ticket_id"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var accountID uuid.UUID
	if body.AccountID != "" {
		accountID, err = uuid.Parse(body.AccountID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid account_id")
			return
		}
	}
	bypass := rbac.HasPermission(sess.Permissions, "users.write")
	if s.itsm != nil && !bypass {
		if err := s.itsm.Enforce(r.Context(), "connect", body.TicketID); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	lease, err := s.apps.RequestK8sAccess(
		r.Context(), sess.UserID, assetID, accountID, sess.Roles, bypass,
		body.TicketID, body.Reason, clientIP(r), r.UserAgent(),
	)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func (s *Server) handleConsumeK8sLease(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "leaseId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.apps.ConsumeLease(r.Context(), sess.UserID, id); err != nil {
		if err == appaccess.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "k8s.lease.consumed", "credential_lease", id.String(), clientIP(r), r.UserAgent(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "consumed"})
}
