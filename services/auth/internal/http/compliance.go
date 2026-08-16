package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/compliance"
)

func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	q := r.URL.Query()
	in := compliance.ReportInput{
		From:      q.Get("from"),
		To:        q.Get("to"),
		Framework: q.Get("framework"),
	}
	if v := q.Get("days"); v != "" {
		if n, err := parseInt(v); err == nil {
			in.Days = n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := parseInt(v); err == nil {
			in.Limit = n
		}
	}
	rep, err := s.compliance.Report(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if strings.EqualFold(q.Get("format"), "csv") {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="keeppam-compliance.csv"`)
		if err := compliance.WriteReportCSV(w, rep); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleComplianceStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.compliance.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleListCompliancePacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.compliance.ListPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleApplyCompliancePack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id := chi.URLParam(r, "id")
	p, err := s.compliance.ApplyPack(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, compliance.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleGetRetention(w http.ResponseWriter, r *http.Request) {
	p, err := s.compliance.GetRetention(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handlePutRetention(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in compliance.RetentionInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.compliance.PutRetention(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleListLegalHolds(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") == "1" || r.URL.Query().Get("active") == "true"
	list, err := s.compliance.ListHolds(r.Context(), activeOnly)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": list})
}

func (s *Server) handleCreateLegalHold(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in compliance.CreateHoldInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	h, err := s.compliance.CreateHold(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) handleReleaseLegalHold(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.compliance.ReleaseHold(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, compliance.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleCompliancePurge(w http.ResponseWriter, r *http.Request) {
	stats, err := s.compliance.Purge(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
