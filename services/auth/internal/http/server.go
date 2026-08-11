package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/analytics"
	"github.com/keeppam/auth/internal/appaccess"
	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/attacksim"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/auth"
	"github.com/keeppam/auth/internal/compliance"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/dbephemeral"
	"github.com/keeppam/auth/internal/discovery"
	"github.com/keeppam/auth/internal/dr"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/settings"
	"github.com/keeppam/auth/internal/siem"
	"github.com/keeppam/auth/internal/sshca"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/users"
)

const (
	sessionCookie = "kp_session"
	csrfCookie    = "kp_csrf"
	csrfHeader    = "X-CSRF-Token"
)

type Server struct {
	cfg        config.Config
	auth       *auth.Service
	users      *users.Service
	assets     *assets.Service
	policy     *policy.Service
	sessionsvc *sessionsvc.Service
	audit      *audit.Service
	sessions   *session.Store
	live       *sessionsvc.LiveHub
	settings   *settings.Service
	siem       *siem.Service
	discovery  *discovery.Service
	analytics  *analytics.Service
	apps       *appaccess.Service
	compliance *compliance.Service
	dr         *dr.Service
	dbEph      *dbephemeral.Service
	attacksim  *attacksim.Service
	sshca      *sshca.Service
}

func New(cfg config.Config, authSvc *auth.Service, usersSvc *users.Service, assetsSvc *assets.Service, policySvc *policy.Service, sessSvc *sessionsvc.Service, auditSvc *audit.Service, sessions *session.Store, live *sessionsvc.LiveHub, settingsSvc *settings.Service, siemSvc *siem.Service, discoverySvc *discovery.Service, analyticsSvc *analytics.Service, appsSvc *appaccess.Service, complianceSvc *compliance.Service, drSvc *dr.Service, dbEph *dbephemeral.Service, attackSim *attacksim.Service, sshCA *sshca.Service) http.Handler {
	s := &Server{cfg: cfg, auth: authSvc, users: usersSvc, assets: assetsSvc, policy: policySvc, sessionsvc: sessSvc, audit: auditSvc, sessions: sessions, live: live, settings: settingsSvc, siem: siemSvc, discovery: discoverySvc, analytics: analyticsSvc, apps: appsSvc, compliance: complianceSvc, dr: drSvc, dbEph: dbEph, attacksim: attackSim, sshca: sshCA}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(s.cors)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		// WebSocket without request timeout (long-lived).
		r.Get("/sessions/{id}/ws", s.handleSessionWS)
		r.Get("/sessions/{id}/guac", s.handleSessionGuac)
		r.Get("/sessions/{id}/sql", s.handleSessionSQL)
		r.Handle("/sessions/{id}/app", http.HandlerFunc(s.handleSessionApp))
		r.Handle("/sessions/{id}/app/*", http.HandlerFunc(s.handleSessionApp))

		// guacenc encode can take minutes.
		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Use(s.requireCSRF)
			r.With(s.requirePerm("sessions.read")).Post("/admin/sessions/{id}/export-mp4", s.handleExportMP4)
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.Timeout(30 * time.Second))

			r.Route("/auth", func(r chi.Router) {
				r.Post("/login", s.handleLogin)
				r.Post("/mfa/verify", s.handleMFAVerify)
				r.Get("/methods", s.handleAuthMethods)
				r.Get("/oidc/start", s.handleOIDCStart)
				r.Get("/oidc/callback", s.handleOIDCCallback)
				r.Group(func(r chi.Router) {
					r.Use(s.requireSession)
					r.Use(s.requireCSRF)
					r.Post("/logout", s.handleLogout)
					r.Get("/me", s.handleMe)
					r.Post("/password", s.handleChangePassword)
					r.Post("/mfa/setup", s.handleMFASetup)
					r.Post("/mfa/confirm", s.handleMFAConfirm)
				})
			})

			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireSession)
				r.Use(s.requireCSRF)
				r.With(s.requirePerm("settings.write")).Get("/settings/auth", s.handleGetAuthSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/auth", s.handlePutAuthSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/siem", s.handleGetSIEMSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/siem", s.handlePutSIEMSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/ssh", s.handleGetSSHSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/ssh", s.handlePutSSHSettings)

				r.With(s.requirePerm("discovery.read")).Get("/discovery/jobs", s.handleListDiscoveryJobs)
				r.With(s.requirePerm("discovery.run")).Post("/discovery/jobs", s.handleCreateDiscoveryJob)
				r.With(s.requirePerm("discovery.read")).Get("/discovery/jobs/{id}", s.handleGetDiscoveryJob)
				r.With(s.requirePerm("discovery.read")).Get("/discovery/jobs/{id}/candidates", s.handleListDiscoveryCandidates)
				r.With(s.requirePerm("assets.write")).Post("/discovery/candidates/{id}/import", s.handleImportDiscoveryCandidate)
				r.With(s.requirePerm("users.read")).Get("/users", s.handleListUsers)
				r.With(s.requirePerm("users.write")).Post("/users", s.handleCreateUser)
				r.With(s.requirePerm("users.read")).Get("/users/{id}", s.handleGetUser)
				r.With(s.requirePerm("users.write")).Patch("/users/{id}", s.handleUpdateUser)
				r.With(s.requirePerm("users.write")).Post("/users/{id}/password/reset", s.handleResetPassword)
				r.With(s.requirePerm("users.reset_mfa")).Post("/users/{id}/mfa/reset", s.handleResetMFA)
				r.With(s.requirePerm("users.read")).Get("/users/{id}/ssh-keys", s.handleListUserSSHKeys)
				r.With(s.requirePerm("users.write")).Post("/users/{id}/ssh-keys", s.handleAddUserSSHKey)
				r.With(s.requirePerm("users.write")).Delete("/users/{id}/ssh-keys/{keyId}", s.handleDeleteUserSSHKey)
				r.With(s.requirePerm("users.read")).Get("/roles", s.handleListRoles)
				r.With(s.requirePerm("audit.read")).Get("/audit-events", s.handleListAudit)
				r.With(s.requirePerm("audit.read")).Get("/analytics/overview", s.handleAnalyticsOverview)

				r.With(s.requirePerm("compliance.read")).Get("/compliance/status", s.handleComplianceStatus)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/packs", s.handleListCompliancePacks)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/packs/{id}/apply", s.handleApplyCompliancePack)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/retention", s.handleGetRetention)
				r.With(s.requirePerm("compliance.write")).Put("/compliance/retention", s.handlePutRetention)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/legal-holds", s.handleListLegalHolds)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/legal-holds", s.handleCreateLegalHold)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/legal-holds/{id}/release", s.handleReleaseLegalHold)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/purge", s.handleCompliancePurge)

				r.With(s.requirePerm("compliance.read")).Get("/dr/status", s.handleDRStatus)
				r.With(s.requirePerm("compliance.read")).Get("/dr/settings", s.handleGetDRSettings)
				r.With(s.requirePerm("compliance.write")).Put("/dr/settings", s.handlePutDRSettings)
				r.With(s.requirePerm("compliance.write")).Post("/dr/backup", s.handleDRBackup)
				r.With(s.requirePerm("compliance.write")).Post("/dr/drill", s.handleDRDrill)

				r.With(s.requirePerm("apps.read")).Get("/assets/{id}/app", s.handleGetAppIntegration)
				r.With(s.requirePerm("apps.write")).Put("/assets/{id}/app", s.handlePutAppIntegration)
				r.With(s.requirePerm("sessions.connect")).Post("/assets/{id}/app/access", s.handleAppAccess)

				r.With(s.requirePerm("assets.read")).Get("/assets", s.handleListAssets)
				r.With(s.requirePerm("assets.write")).Post("/assets", s.handleCreateAsset)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}", s.handleGetAsset)
				r.With(s.requirePerm("assets.write")).Patch("/assets/{id}", s.handleUpdateAsset)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}", s.handleDeleteAsset)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}/host-key", s.handleClearAssetHostKey)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts", s.handleCreateAccount)
				r.With(s.requirePerm("assets.write")).Patch("/assets/{id}/accounts/{accountId}", s.handleUpdateAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/rotate", s.handleRotateAccount)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}/accounts/{accountId}", s.handleDeleteAccount)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}/acl", s.handleListACL)
				r.With(s.requirePerm("assets.acl")).Post("/assets/{id}/acl", s.handleCreateACL)
				r.With(s.requirePerm("assets.acl")).Delete("/assets/{id}/acl/{bindingId}", s.handleDeleteACL)

				r.With(s.requirePerm("jea.read")).Get("/jea/packs", s.handleListCommandPacks)
				r.With(s.requirePerm("jea.read")).Get("/jea/packs/{id}", s.handleGetCommandPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/packs", s.handleCreateCommandPack)
				r.With(s.requirePerm("jea.write")).Put("/jea/packs/{id}", s.handleUpdateCommandPack)
				r.With(s.requirePerm("jea.write")).Delete("/jea/packs/{id}", s.handleDeleteCommandPack)

				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/scenarios", s.handleListAttackScenarios)
				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/runs", s.handleListAttackRuns)
				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/runs/{id}", s.handleGetAttackRun)
				r.With(s.requirePerm("attacksim.write")).Post("/attack-sim/runs", s.handleStartAttackRun)

				r.With(s.requirePerm("access.request")).Post("/assets/{id}/access-requests", s.handleCreateAccessRequest)
				r.With(s.requirePerm("access.request")).Get("/access-requests", s.handleListAccessRequests)
				r.With(s.requirePerm("access.request")).Get("/access-requests/summary", s.handleAccessRequestsSummary)
				r.With(s.requirePerm("access.approve")).Post("/access-requests/{id}/approve", s.handleApproveAccessRequest)
				r.With(s.requirePerm("access.approve")).Post("/access-requests/{id}/deny", s.handleDenyAccessRequest)
				r.With(s.requirePerm("access.request")).Post("/access-requests/{id}/cancel", s.handleCancelAccessRequest)

				r.With(s.requirePerm("sessions.connect")).Post("/sessions", s.handleCreateSession)
				r.With(s.requirePerm("sessions.connect")).Post("/sessions/{id}/end", s.handleEndSession)
				r.With(s.requirePerm("sessions.read")).Get("/sessions", s.handleListSessions)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}", s.handleGetSession)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}/recording", s.handleGetRecording)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}/recording.mp4", s.handleGetRecordingMP4)
			})
		})
	})

	return r
}

type ctxKey int

const sessKey ctxKey = 1

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == s.cfg.CORSOrigin || s.cfg.CORSOrigin == "*" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "X-CSRF-Token")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sess, err := s.sessions.Get(r.Context(), c.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// Refresh roles/permissions from DB so RBAC changes apply without re-login.
		if u, err := s.auth.Me(r.Context(), sess.UserID); err == nil {
			sess.Roles = u.Roles
			sess.Permissions = u.Permissions
		}
		ctx := context.WithValue(r.Context(), sessKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(csrfCookie)
		if err != nil || cookie.Value == "" {
			writeErr(w, http.StatusForbidden, "csrf missing")
			return
		}
		header := r.Header.Get(csrfHeader)
		if header == "" || header != cookie.Value {
			writeErr(w, http.StatusForbidden, "csrf invalid")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mustSess(r)
			if !rbac.HasPermission(sess.Permissions, perm) {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func mustSess(r *http.Request) session.Session {
	return r.Context().Value(sessKey).(session.Session)
}

func (s *Server) setSessionCookies(w http.ResponseWriter, sessionToken string) error {
	csrf, err := session.CSRFToken()
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sessionToken, Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Domain: s.cfg.CookieDomain,
		MaxAge: int(s.cfg.SessionTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Domain: s.cfg.CookieDomain,
		MaxAge: int(s.cfg.SessionTTL.Seconds()),
	})
	w.Header().Set(csrfHeader, csrf)
	return nil
}

func (s *Server) clearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", MaxAge: -1})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.auth.Login(r.Context(), body.Username, body.Password, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if res.SessionToken != "" {
		if err := s.setSessionCookies(w, res.SessionToken); err != nil {
			writeErr(w, http.StatusInternalServerError, "session error")
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeToken string `json:"challenge_token"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.auth.VerifyMFA(r.Context(), body.ChallengeToken, body.Code, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.setSessionCookies(w, res.SessionToken); err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	c, _ := r.Cookie(sessionCookie)
	token := ""
	if c != nil {
		token = c.Value
	}
	_ = s.auth.Logout(r.Context(), token, &sess.UserID, clientIP(r), r.UserAgent())
	s.clearCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	u, err := s.auth.Me(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.ChangePassword(r.Context(), sess.UserID, body.Current, body.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	setup, err := s.auth.BeginMFASetup(r.Context(), sess.UserID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, setup)
}

func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.ConfirmMFASetup(r.Context(), sess.UserID, body.Code, clientIP(r), r.UserAgent()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.users.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": list})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in users.CreateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.users.Create(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	u, err := s.users.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in users.UpdateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.users.Update(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	temp, err := s.users.ResetPassword(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"temporary_password": temp})
}

func (s *Server) handleResetMFA(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.users.ResetMFA(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListUserSSHKeys(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	keys, err := s.users.ListSSHKeys(r.Context(), id)
	if err != nil {
		if users.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleAddUserSSHKey(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in users.AddSSHKeyInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	key, err := s.users.AddSSHKey(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) handleDeleteUserSSHKey(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	keyID, err := uuid.Parse(chi.URLParam(r, "keyId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid key id")
		return
	}
	if err := s.users.DeleteSSHKey(r.Context(), sess.UserID, id, keyID, clientIP(r), r.UserAgent()); err != nil {
		if err.Error() == "not found" {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.users.ListRoles(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{Limit: 50, Offset: 0}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Offset = (n - 1) * f.Limit
		}
	}
	if v := r.URL.Query().Get("action"); v != "" {
		f.Action = v
	}
	if v := r.URL.Query().Get("q"); v != "" {
		f.Q = v
	}
	if v := r.URL.Query().Get("field"); v != "" {
		f.SearchField = v
	}
	if v := r.URL.Query().Get("actor_id"); v != "" {
		id, err := uuid.Parse(v)
		if err == nil {
			f.ActorID = &id
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	events, total, err := s.audit.List(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	page := 1
	if f.Limit > 0 {
		page = f.Offset/f.Limit + 1
	}
	pages := 0
	if f.Limit > 0 && total > 0 {
		pages = (total + f.Limit - 1) / f.Limit
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
		"page":   page,
		"pages":  pages,
	})
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	list, err := s.assets.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": list})
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in assets.CreateAssetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.assets.Create(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
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

func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in assets.UpdateAssetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, err := s.assets.Update(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		if assets.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleClearAssetHostKey(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	a, err := s.assets.ClearHostKey(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent())
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

func (s *Server) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.assets.Delete(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent()); err != nil {
		if assets.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in assets.CreateAccountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	acc, err := s.assets.CreateAccount(r.Context(), sess.UserID, assetID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, acc)
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	var in assets.UpdateAccountInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	acc, err := s.assets.UpdateAccount(r.Context(), sess.UserID, accountID, in, clientIP(r), r.UserAgent())
	if err != nil {
		if assets.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handleRotateAccount(w http.ResponseWriter, r *http.Request) {
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
	var in assets.RotateInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.assets.RotateSecret(r.Context(), sess.UserID, assetID, accountID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	if err := s.assets.DeleteAccount(r.Context(), sess.UserID, accountID, clientIP(r), r.UserAgent()); err != nil {
		if assets.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListACL(w http.ResponseWriter, r *http.Request) {
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	list, err := s.policy.ListByAsset(r.Context(), assetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": list})
}

func (s *Server) handleCreateACL(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.CreateBindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, err := s.policy.Create(r.Context(), sess.UserID, assetID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	bindingID, err := uuid.Parse(chi.URLParam(r, "bindingId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid binding id")
		return
	}
	if err := s.policy.Delete(r.Context(), sess.UserID, bindingID, clientIP(r), r.UserAgent()); err != nil {
		if policy.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
