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
	if s.itsm != nil {
		if err := s.itsm.Enforce(r.Context(), "request", in.TicketID); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	req, err := s.policy.CreateRequest(r.Context(), sess.UserID, assetID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		s.notify.OnJITCreated(r.Context(), req)
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
		rbac.HasPermission(sess.Permissions, "access.approve.security") ||
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
	pending, gerr := s.policy.GetRequest(r.Context(), id)
	if gerr == nil {
		need := policy.StagePermission(pending.Stage)
		if !rbac.HasPermission(sess.Permissions, need) {
			writeErr(w, http.StatusForbidden, "this stage requires "+need)
			return
		}
		if s.itsm != nil {
			if err := s.itsm.Enforce(r.Context(), "approve", pending.TicketID); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	req, err := s.policy.ApproveRequest(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsRequestNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		if req.Status == "pending" {
			s.notify.OnJITStage(r.Context(), req)
		} else {
			s.notify.OnJITDecided(r.Context(), req)
		}
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
	req, err := s.policy.DenyRequest(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsRequestNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		s.notify.OnJITDecided(r.Context(), req)
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
	req, err := s.policy.CancelRequest(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
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
	canManager := rbac.HasPermission(sess.Permissions, "access.approve") ||
		rbac.HasPermission(sess.Permissions, "assets.acl")
	canSecurity := rbac.HasPermission(sess.Permissions, "access.approve.security")
	sum, err := s.policy.RequestsSummary(r.Context(), sess.UserID, canManager, canSecurity)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleOpenBreakGlass(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.BreakGlassInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ev, err := s.policy.OpenBreakGlass(r.Context(), sess.UserID, assetID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ev)
}

func (s *Server) handleListBreakGlass(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("all") != "1"
	list, err := s.policy.ListBreakGlass(r.Context(), activeOnly)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": list})
}
