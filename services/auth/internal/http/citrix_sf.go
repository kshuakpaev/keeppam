package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/citrix"
)

// GET /api/v1/admin/assets/{id}/citrix/resources — StoreFront read-only enumeration (phase 2).
func (s *Server) handleCitrixSFResources(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	a, err := s.assets.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	if a.Protocol != "citrix" {
		writeErr(w, http.StatusBadRequest, "not a citrix asset")
		return
	}
	if strings.TrimSpace(a.CitrixStoreFrontURL) == "" {
		writeErr(w, http.StatusBadRequest, "citrix_storefront_url not set")
		return
	}

	user, pass := "", ""
	if accID := r.URL.Query().Get("account_id"); accID != "" {
		aid, err := uuid.Parse(accID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad account_id")
			return
		}
		creds, err := s.assets.GetTargetCreds(r.Context(), id, aid)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		user, pass = creds.Account.Username, creds.Secret
	} else if len(a.Accounts) > 0 {
		creds, err := s.assets.GetTargetCreds(r.Context(), id, a.Accounts[0].ID)
		if err == nil {
			user, pass = creds.Account.Username, creds.Secret
		}
	}

	cli := &citrix.StoreFrontClient{
		BaseURL:  a.CitrixStoreFrontURL,
		User:     user,
		Password: pass,
	}
	list, err := cli.ListResources(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "storefront: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id":   id.String(),
		"storefront": a.CitrixStoreFrontURL,
		"count":      len(list),
		"resources":  list,
	})
}

// GET /api/v1/admin/assets/{id}/citrix/discovery
func (s *Server) handleCitrixSFDiscovery(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	a, err := s.assets.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "asset not found")
		return
	}
	if strings.TrimSpace(a.CitrixStoreFrontURL) == "" {
		writeErr(w, http.StatusBadRequest, "citrix_storefront_url not set")
		return
	}
	cli := &citrix.StoreFrontClient{BaseURL: a.CitrixStoreFrontURL}
	doc, err := cli.Discovery(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "storefront discovery: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": id.String(), "discovery": doc})
}
