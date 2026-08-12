package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/keeppam/auth/internal/settings"
	"github.com/keeppam/auth/internal/siem"
	"github.com/keeppam/auth/internal/itsm"
	"github.com/keeppam/auth/internal/sshca"
)

func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	m, err := s.settings.PublicMethods(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleGetAuthSettings(w http.ResponseWriter, r *http.Request) {
	cfg, _, _, err := s.settings.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.OIDCClientSecret = ""
	cfg.LDAPBindPassword = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutAuthSettings(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in settings.AuthSettings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.settings.Update(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out.OIDCClientSecret = ""
	out.LDAPBindPassword = ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSIEMSettings(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.siem.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.WebhookAuthHeader = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleGetSSHSettings(w http.ResponseWriter, r *http.Request) {
	if s.sshca == nil {
		writeErr(w, http.StatusServiceUnavailable, "ssh settings unavailable")
		return
	}
	cfg, err := s.sshca.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutSSHSettings(w http.ResponseWriter, r *http.Request) {
	if s.sshca == nil {
		writeErr(w, http.StatusServiceUnavailable, "ssh settings unavailable")
		return
	}
	sess := mustSess(r)
	var in sshca.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.sshca.Update(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutSIEMSettings(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in siem.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.siem.Update(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out.WebhookAuthHeader = ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetITSMSettings(w http.ResponseWriter, r *http.Request) {
	if s.itsm == nil {
		writeErr(w, http.StatusInternalServerError, "itsm not configured")
		return
	}
	cfg, _, err := s.itsm.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.AuthHeader = ""
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handlePutITSMSettings(w http.ResponseWriter, r *http.Request) {
	if s.itsm == nil {
		writeErr(w, http.StatusInternalServerError, "itsm not configured")
		return
	}
	sess := mustSess(r)
	var in itsm.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	out, err := s.itsm.Update(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out.AuthHeader = ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleITSMValidate(w http.ResponseWriter, r *http.Request) {
	if s.itsm == nil {
		writeErr(w, http.StatusInternalServerError, "itsm not configured")
		return
	}
	var body struct {
		TicketID string `json:"ticket_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	info, err := s.itsm.Validate(r.Context(), body.TicketID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	cfg, oidcSec, _, err := s.settings.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.Mode != "oidc" {
		writeErr(w, http.StatusBadRequest, "oidc is not enabled")
		return
	}
	secret, err := s.settings.DecryptSecret(oidcSec)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	url, err := s.settings.OIDCAuthCodeURL(r.Context(), s.sessions.Redis(), cfg, secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	cfg, oidcSec, _, err := s.settings.Get(r.Context())
	base := cfg.PublicBaseURL
	if base == "" {
		base = s.cfg.CORSOrigin
	}
	if err != nil {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, "settings error"), http.StatusFound)
		return
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, errMsg), http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, "missing code"), http.StatusFound)
		return
	}
	secret, err := s.settings.DecryptSecret(oidcSec)
	if err != nil {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, "secret error"), http.StatusFound)
		return
	}
	claims, err := s.settings.OIDCExchange(r.Context(), s.sessions.Redis(), cfg, secret, code, state)
	if err != nil {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, err.Error()), http.StatusFound)
		return
	}
	res, err := s.auth.LoginOIDC(r.Context(), claims, clientIP(r), r.UserAgent())
	if err != nil {
		http.Redirect(w, r, settings.OIDCErrorRedirect(base, err.Error()), http.StatusFound)
		return
	}
	if res.SessionToken != "" {
		_ = s.setSessionCookies(w, res.SessionToken)
	}
	if res.Status == "mfa_required" && res.ChallengeToken != "" {
		http.Redirect(w, r, base+"/login?mfa="+res.ChallengeToken, http.StatusFound)
		return
	}
	dest := settings.OIDCSuccessRedirect(base)
	if res.Status == "must_setup" {
		dest = base + "/setup"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	cfg, _, _, err := s.settings.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !cfg.HasSAMLSPKey {
		writeErr(w, http.StatusBadRequest, "saml sp key not generated; save mode=saml in settings first")
		return
	}
	xmlBytes, err := s.settings.SAMLMetadataXML(r.Context(), cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(xmlBytes)
}

func (s *Server) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	cfg, _, _, err := s.settings.Get(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.Mode != "saml" {
		writeErr(w, http.StatusBadRequest, "saml is not enabled")
		return
	}
	u, err := s.settings.SAMLAuthRedirect(r.Context(), s.sessions.Redis(), cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	cfg, _, _, err := s.settings.Get(r.Context())
	base := cfg.PublicBaseURL
	if base == "" {
		base = s.cfg.CORSOrigin
	}
	if err != nil {
		http.Redirect(w, r, settings.SAMLErrorRedirect(base, "settings error"), http.StatusFound)
		return
	}
	if cfg.Mode != "saml" {
		http.Redirect(w, r, settings.SAMLErrorRedirect(base, "saml is not enabled"), http.StatusFound)
		return
	}
	claims, err := s.settings.SAMLParseACS(r.Context(), s.sessions.Redis(), cfg, r)
	if err != nil {
		http.Redirect(w, r, settings.SAMLErrorRedirect(base, err.Error()), http.StatusFound)
		return
	}
	res, err := s.auth.LoginSAML(r.Context(), claims, clientIP(r), r.UserAgent())
	if err != nil {
		http.Redirect(w, r, settings.SAMLErrorRedirect(base, err.Error()), http.StatusFound)
		return
	}
	if res.SessionToken != "" {
		_ = s.setSessionCookies(w, res.SessionToken)
	}
	if res.Status == "mfa_required" && res.ChallengeToken != "" {
		http.Redirect(w, r, base+"/login?mfa="+res.ChallengeToken, http.StatusFound)
		return
	}
	dest := settings.SAMLSuccessRedirect(base)
	if res.Status == "must_setup" {
		dest = base + "/setup"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
