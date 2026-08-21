package httpapi

import (
	"net/http"
)

func (s *Server) handleCitrixHDXHealth(w http.ResponseWriter, r *http.Request) {
	if s.hdx == nil || !s.hdx.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"status":     "disabled",
			"hint":       "set KEEPPAM_CITRIX_HDX_PLUGIN_URL and asset citrix_transport=hdx",
		})
		return
	}
	h, err := s.hdx.Health(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true, "status": "unreachable", "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true, "status": h.Status, "capabilities": h.Capabilities,
		"vendor": h.Vendor, "version": h.Version, "plugin_url": s.cfg.CitrixHDXPluginURL,
	})
}
