package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
)

func (s *Server) handleCreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.CreateRequestInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req, err := s.policy.CreateRequest(r.Context(), sess.UserID, assetID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) handleListAccessRequests(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	f := policy.ListRequestsFilter{
		Status: r.URL.Query().Get("status"),
		Limit:  50,
		Offset: 0,
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
	// Approvers see all (optionally filtered); others see own.
	canApprove := rbac.HasPermission(sess.Permissions, "access.approve") ||
		rbac.HasPermission(sess.Permissions, "assets.acl")
	if !canApprove {
		f.RequesterID = &sess.UserID
	}
	list, total, err := s.policy.ListRequests(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": list, "total": total})
}

func (s *Server) handleApproveAccessRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	req, err := s.policy.ApproveRequest(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsRequestNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleDenyAccessRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	req, err := s.policy.DenyRequest(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsRequestNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleCancelAccessRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	req, err := s.policy.CancelRequest(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsRequestNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleAccessRequestsSummary(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	canApprove := rbac.HasPermission(sess.Permissions, "access.approve") ||
		rbac.HasPermission(sess.Permissions, "assets.acl")
	sum, err := s.policy.RequestsSummary(r.Context(), sess.UserID, canApprove)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
