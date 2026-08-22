package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/keeppam/auth/internal/geo"
)

func (s *Server) geoConfig() geo.Config {
	return geo.Config{
		SiteID:        s.cfg.SiteID,
		Role:          s.cfg.SiteRole,
		PeerURL:       s.cfg.SitePeerURL,
		ReplicaDSN:    s.cfg.SiteReplicaDSN,
		MaxLagSeconds: s.cfg.SiteMaxLagSeconds,
	}
}

func (s *Server) handleGeoStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st := geo.Probe(ctx, s.geoConfig())
	writeJSON(w, http.StatusOK, st)
}

// Unauthenticated site postcard for peer health (no secrets / lag DSN details beyond ok|error).
func (s *Server) handleGeoPublic(w http.ResponseWriter, r *http.Request) {
	cfg := s.geoConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"site_id": cfg.SiteID, "role": geo.NormalizeRole(cfg.Role),
		"allows_writes": cfg.AllowsSessionWrites(),
	})
}

func (s *Server) fenceStandbySessions(w http.ResponseWriter) bool {
	cfg := s.geoConfig()
	if err := geo.FenceError(cfg); err != nil {
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return true
	}
	return false
}
