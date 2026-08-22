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

func (s *Server) geoRecordingsConfig() geo.RecordingsConfig {
	return geo.RecordingsConfig{
		Mode:              s.cfg.GeoRecordingsSync,
		LocalDir:          s.cfg.RecordingsDir,
		RecordingsBackend: s.cfg.RecordingsBackend,
		S3Bucket:          s.cfg.S3Bucket,
		S3Prefix:          s.cfg.S3Prefix,
		RsyncTarget:       s.cfg.GeoRsyncTarget,
		RsyncSource:       s.cfg.GeoRsyncSource,
	}
}

func (s *Server) handleGeoStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st := geo.Probe(ctx, s.geoConfig())
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGeoRecordings(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	last := geo.LoadLastSync(ctx, s.sessions.Redis())
	st, err := geo.RecordingsStatusOf(s.geoRecordingsConfig(), last)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGeoRecordingsSync(w http.ResponseWriter, r *http.Request) {
	cfg := s.geoRecordingsConfig()
	if cfg.SyncMode() != "rsync" {
		writeErr(w, http.StatusBadRequest, "geo recordings sync mode is not rsync")
		return
	}
	if s.geoConfig().IsStandby() {
		writeErr(w, http.StatusBadRequest, "rsync push runs on primary site")
		return
	}
	src := cfg.LocalDir
	if cfg.RsyncSource != "" {
		src = cfg.RsyncSource
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	inv, err := geo.RsyncOnce(ctx, src, cfg.RsyncTarget)
	ls := geo.LastSync{At: time.Now().UTC(), Mode: "rsync", Files: inv.Files, Bytes: inv.Bytes, Target: cfg.RsyncTarget}
	if err != nil {
		ls.Error = err.Error()
		geo.SaveLastSync(ctx, s.sessions.Redis(), ls, 0)
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	geo.SaveLastSync(ctx, s.sessions.Redis(), ls, 0)
	writeJSON(w, http.StatusOK, map[string]any{"synced": true, "inventory": inv, "last_sync": ls})
}

func (s *Server) handleGeoPromotePlan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	gcfg := s.geoConfig()
	st := geo.Probe(ctx, gcfg)
	last := geo.LoadLastSync(ctx, s.sessions.Redis())
	rec, err := geo.RecordingsStatusOf(s.geoRecordingsConfig(), last)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, geo.BuildPromotePlan(gcfg, rec, st))
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
