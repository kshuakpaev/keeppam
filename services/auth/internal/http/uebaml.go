package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/uebaml"
)

func (s *Server) handleGetUEBAMLSettings(w http.ResponseWriter, r *http.Request) {
	if s.uebaml == nil {
		writeErr(w, http.StatusServiceUnavailable, "ueba ml unavailable")
		return
	}
	cfg, err := s.uebaml.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutUEBAMLSettings(w http.ResponseWriter, r *http.Request) {
	if s.uebaml == nil {
		writeErr(w, http.StatusServiceUnavailable, "ueba ml unavailable")
		return
	}
	sess := mustSess(r)
	var in uebaml.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.uebaml.Put(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUEBAMLTest(w http.ResponseWriter, r *http.Request) {
	if s.uebaml == nil {
		writeErr(w, http.StatusServiceUnavailable, "ueba ml unavailable")
		return
	}
	var body struct {
		UserID  string `json:"user_id"`
		AssetID string `json:"asset_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sess := mustSess(r)
	userID := sess.UserID
	var assetID uuid.UUID
	if body.UserID != "" {
		if id, err := uuid.Parse(body.UserID); err == nil {
			userID = id
		}
	}
	if body.AssetID != "" {
		if id, err := uuid.Parse(body.AssetID); err == nil {
			assetID = id
		}
	}
	score, factors, res, err := s.uebaml.EnhanceConnect(r.Context(), userID, assetID, 0, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": map[string]any{
			"risk_score": score, "risk_factors": factors, "connect": res,
		},
	})
}
