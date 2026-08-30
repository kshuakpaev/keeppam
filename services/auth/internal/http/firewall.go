package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/firewall"
)

func (s *Server) handleGetFirewallSettings(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	cfg, err := s.firewall.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutFirewallSettings(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	sess := mustSess(r)
	var in firewall.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.firewall.Put(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	st, err := s.firewall.Status(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleFirewallProbe(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	sess := mustSess(r)
	rep, err := s.firewall.Probe(r.Context(), sess.UserID, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handlePutFirewallProbeAgents(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	sess := mustSess(r)
	var in struct {
		ProbeQuorum int                        `json:"probe_quorum"`
		Agents      []firewall.ProbeAgentInput `json:"agents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	quorum := in.ProbeQuorum
	if quorum < 1 {
		quorum = 1
	}
	agents, err := s.firewall.ReplaceProbeAgents(r.Context(), sess.UserID, quorum, in.Agents, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"probe_quorum": quorum, "agents": agents})
}

func (s *Server) handleFirewallPush(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	sess := mustSess(r)
	if err := s.firewall.PushAWX(r.Context(), sess.UserID, s.clientIP(r), r.UserAgent()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg, err := s.firewall.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleMarkFirewallApplied(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if !s.requireOwnedAssetID(w, r, id) {
		return
	}
	if err := s.firewall.MarkApplied(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, firewall.ErrNotPamOnly) {
			writeErr(w, http.StatusNotFound, "not found or not pam_only")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a, err := s.assets.Get(r.Context(), id)
	if err != nil {
		if assets.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleExportFirewallRules(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		writeErr(w, http.StatusServiceUnavailable, "firewall unavailable")
		return
	}
	format := strings.TrimSpace(r.URL.Query().Get("format"))
	if format == "" {
		format = "iptables"
	}
	body, err := s.firewall.Export(r.Context(), format)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	filename := "keeppam-firewall." + format
	switch format {
	case "nft", "nftables":
		filename = "keeppam-firewall.nft"
	case "ansible", "yaml":
		filename = "keeppam-firewall.yml"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(body))
}
