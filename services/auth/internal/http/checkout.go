package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func (s *Server) handleCheckoutAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	var in assets.CheckoutInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.assets.Checkout(r.Context(), sess.UserID, assetID, accountID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil && res.Pending != nil {
		s.notify.OnCheckoutCreated(r.Context(), *res.Pending)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCheckinAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	var in assets.CheckinInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.assets.Checkin(r.Context(), sess.UserID, assetID, accountID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleForceCheckinAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	acc, err := s.assets.ForceCheckin(r.Context(), sess.UserID, assetID, accountID, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleRevealAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	res, err := s.assets.RevealSecret(r.Context(), sess.UserID, assetID, accountID, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListCheckoutRequests(w http.ResponseWriter, r *http.Request) {
	onlyPending := r.URL.Query().Get("pending") != "0"
	list, err := s.assets.ListCheckoutRequests(r.Context(), onlyPending)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": list})
}

func (s *Server) handleApproveCheckoutRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	res, err := s.assets.ApproveCheckoutRequest(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil && res.Pending != nil {
		decided := *res.Pending
		decided.Status = "approved"
		s.notify.OnCheckoutDecided(r.Context(), decided)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDenyCheckoutRequest(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	req, err := s.assets.DenyCheckoutRequest(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.notify != nil {
		s.notify.OnCheckoutDecided(r.Context(), req)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}
