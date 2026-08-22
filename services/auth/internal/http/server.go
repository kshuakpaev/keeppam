package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	"github.com/keeppam/auth/internal/castindex"
	"github.com/keeppam/auth/internal/citrix/hdx"
	"github.com/keeppam/auth/internal/compliance"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/dbephemeral"
	"github.com/keeppam/auth/internal/device"
	"github.com/keeppam/auth/internal/discovery"
	"github.com/keeppam/auth/internal/dr"
	"github.com/keeppam/auth/internal/eidas"
	"github.com/keeppam/auth/internal/filexfer"
	"github.com/keeppam/auth/internal/firewall"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/health"
	"github.com/keeppam/auth/internal/itsm"
	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/license"
	"github.com/keeppam/auth/internal/nac"
	"github.com/keeppam/auth/internal/notify"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/opapprove"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/recarch"
	"github.com/keeppam/auth/internal/rdpgw"
	"github.com/keeppam/auth/internal/scim"
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
	itsm       *itsm.Service
	notify     *notify.Service
	k8s        *k8sproxy.Gateway
	ops        *opapprove.Service
	scim       *scim.Service
	castidx    *castindex.Service
	firewall   *firewall.Service
	nac        *nac.Service
	eidas      *eidas.Service
	archive    *recarch.Service
	files      *filexfer.Service
	health     *health.State
	rdp        *rdpgw.Broker
	hdx        *hdx.Client
	license    license.File
}

func New(cfg config.Config, authSvc *auth.Service, usersSvc *users.Service, assetsSvc *assets.Service, policySvc *policy.Service, sessSvc *sessionsvc.Service, auditSvc *audit.Service, sessions *session.Store, live *sessionsvc.LiveHub, settingsSvc *settings.Service, siemSvc *siem.Service, discoverySvc *discovery.Service, analyticsSvc *analytics.Service, appsSvc *appaccess.Service, complianceSvc *compliance.Service, drSvc *dr.Service, dbEph *dbephemeral.Service, attackSim *attacksim.Service, sshCA *sshca.Service, itsmSvc *itsm.Service, notifySvc *notify.Service, k8sGw *k8sproxy.Gateway, ops *opapprove.Service, scimSvc *scim.Service, firewallSvc *firewall.Service, nacSvc *nac.Service, eidasSvc *eidas.Service, archiveSvc *recarch.Service, filesSvc *filexfer.Service, life *health.State, rdpBroker *rdpgw.Broker, castIdx *castindex.Service) http.Handler {
	lic, err := license.Load(cfg.LicenseFile)
	if err != nil {
		lic = license.DefaultFile()
		lic.Source = "error:" + err.Error()
	}
	s := &Server{cfg: cfg, auth: authSvc, users: usersSvc, assets: assetsSvc, policy: policySvc, sessionsvc: sessSvc, audit: auditSvc, sessions: sessions, live: live, settings: settingsSvc, siem: siemSvc, discovery: discoverySvc, analytics: analyticsSvc, apps: appsSvc, compliance: complianceSvc, dr: drSvc, dbEph: dbEph, attacksim: attackSim, sshca: sshCA, itsm: itsmSvc, notify: notifySvc, k8s: k8sGw, ops: ops, scim: scimSvc, firewall: firewallSvc, nac: nacSvc, eidas: eidasSvc, archive: archiveSvc, files: filesSvc, health: life, rdp: rdpBroker, castidx: castIdx, license: lic, hdx: hdx.NewClient(cfg.CitrixHDXPluginURL)}
	if s.castidx == nil && sessSvc != nil {
		s.castidx = castindex.New(sessSvc, sessSvc.RecordingStore(), cfg.GuacencURL)
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(obs.HTTPTracing)
	r.Use(s.metricsMW)
	r.Use(s.cors)

	r.Get("/healthz", s.handleLivez)
	r.Get("/livez", s.handleLivez)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/geoz", s.handleGeoPublic)
	r.Get("/metrics", s.handleMetrics)

	// Isolated Chromium → API reverse-proxy (HTTP/object ACL). No cookie; token in path.
	// Outside Timeout: object approval / step-up hold up to 60s.
	r.Handle("/iso/{id}/{token}", http.HandlerFunc(s.handleIsoApp))
	r.Handle("/iso/{id}/{token}/*", http.HandlerFunc(s.handleIsoApp))

	s.mountSCIM(r)

	r.Route("/api/v1", func(r chi.Router) {
		// WebSocket without request timeout (long-lived).
		r.Get("/sessions/{id}/ws", s.handleSessionWS)
		r.Get("/sessions/{id}/watch", s.handleSessionWatch)
		r.Get("/sessions/{id}/guac", s.handleSessionGuac)
		r.Get("/sessions/{id}/sql", s.handleSessionSQL)
		r.Get("/sessions/{id}/k8s/exec", s.handleK8sExecWS)
		r.Get("/sessions/{id}/k8s/attach", s.handleK8sAttachWS)
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

			r.Post("/alerts/webhook", s.handleAlertWebhook)
			r.Get("/citrix/sta/{ticket}", s.handleCitrixSTAValidate)
			r.Get("/Scripts/CtxSta.dll", s.handleCitrixCtxSta)
			r.Get("/citrix/Scripts/CtxSta.dll", s.handleCitrixCtxSta)
			r.Post("/citrix/hdx/ingest", s.handleCitrixHDXIngest)

			r.Route("/auth", func(r chi.Router) {
				r.Post("/login", s.handleLogin)
				r.Post("/login/cert", s.handleLoginCert)
				r.Post("/mfa/verify", s.handleMFAVerify)
				r.Post("/mfa/webauthn/begin", s.handleWebAuthnLoginBegin)
				r.Post("/mfa/webauthn/finish", s.handleWebAuthnLoginFinish)
				r.Get("/methods", s.handleAuthMethods)
				r.Get("/oidc/start", s.handleOIDCStart)
				r.Get("/oidc/callback", s.handleOIDCCallback)
				r.Get("/saml/metadata", s.handleSAMLMetadata)
				r.Get("/saml/start", s.handleSAMLStart)
				r.Post("/saml/acs", s.handleSAMLACS)
				r.Get("/saml/slo", s.handleSAMLSLO)
				r.Post("/saml/slo", s.handleSAMLSLO)
				r.Get("/saml/idp/{slug}/metadata", s.handleSAMLMetadata)
				r.Get("/saml/idp/{slug}/start", s.handleSAMLStart)
				r.Post("/saml/idp/{slug}/acs", s.handleSAMLACS)
				r.Get("/saml/idp/{slug}/slo", s.handleSAMLSLO)
				r.Post("/saml/idp/{slug}/slo", s.handleSAMLSLO)
				r.Group(func(r chi.Router) {
					r.Use(s.requireSession)
					r.Use(s.requireCSRF)
					r.Post("/logout", s.handleLogout)
					r.Get("/me", s.handleMe)
					r.Post("/password", s.handleChangePassword)
					r.Post("/mfa/setup", s.handleMFASetup)
					r.Post("/mfa/confirm", s.handleMFAConfirm)
					r.Post("/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
					r.Post("/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
					r.Get("/webauthn/credentials", s.handleListMyWebAuthn)
					r.Delete("/webauthn/credentials/{id}", s.handleDeleteMyWebAuthn)
					r.Post("/stepup/totp", s.handleStepUpTOTP)
					r.Post("/stepup/webauthn/begin", s.handleStepUpWebAuthnBegin)
					r.Post("/stepup/webauthn/finish", s.handleStepUpWebAuthnFinish)
				})
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireSession)
				r.Use(s.requireCSRF)
				r.Get("/notifications", s.handleListNotifications)
				r.Get("/notifications/unread-count", s.handleUnreadNotifications)
				r.Post("/notifications/read-all", s.handleReadAllNotifications)
				r.Post("/notifications/{id}/read", s.handleReadNotification)
			})

			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireSession)
				r.Use(s.requireCSRF)
				r.With(s.requirePerm("settings.write")).Get("/settings/auth", s.handleGetAuthSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/auth", s.handlePutAuthSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/saml/idps", s.handleListSAMLIdPs)
				r.With(s.requirePerm("settings.write")).Post("/settings/saml/idps", s.handleCreateSAMLIdP)
				r.With(s.requirePerm("settings.write")).Put("/settings/saml/idps/{id}", s.handleUpdateSAMLIdP)
				r.With(s.requirePerm("settings.write")).Delete("/settings/saml/idps/{id}", s.handleDeleteSAMLIdP)
				r.With(s.requirePerm("settings.write")).Get("/settings/siem", s.handleGetSIEMSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/siem", s.handlePutSIEMSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/siem/bulk", s.handleSIEMBulk)
				r.With(s.requirePerm("settings.write")).Get("/settings/itsm", s.handleGetITSMSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/itsm", s.handlePutITSMSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/notify", s.handleGetNotifySettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/notify", s.handlePutNotifySettings)
				r.With(s.requirePerm("settings.write")).Post("/settings/notify/test-email", s.handleTestNotifyEmail)
				r.With(s.requirePerm("settings.write")).Post("/itsm/validate", s.handleITSMValidate)
				r.With(s.requirePerm("settings.write")).Get("/settings/ssh", s.handleGetSSHSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/ssh", s.handlePutSSHSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/firewall", s.handleGetFirewallSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/firewall", s.handlePutFirewallSettings)
				r.With(s.requirePerm("settings.write")).Get("/settings/nac", s.handleGetNACSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/nac", s.handlePutNACSettings)
				r.With(s.requirePerm("settings.write")).Post("/settings/nac/test", s.handleNACTest)
				r.With(s.requirePerm("settings.write")).Get("/settings/eidas", s.handleGetEIDASSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/eidas", s.handlePutEIDASSettings)
				r.With(s.requirePerm("settings.write")).Post("/settings/eidas/test", s.handleEIDASTest)
				r.With(s.requireAnyPerm("settings.write", "assets.read")).Get("/firewall/status", s.handleFirewallStatus)
				r.With(s.requirePerm("settings.write")).Post("/firewall/probe", s.handleFirewallProbe)
				r.With(s.requirePerm("settings.write")).Put("/firewall/probe-agents", s.handlePutFirewallProbeAgents)
				r.With(s.requirePerm("settings.write")).Post("/firewall/push", s.handleFirewallPush)
				r.With(s.requireAnyPerm("settings.write", "assets.read")).Get("/firewall/export", s.handleExportFirewallRules)
				r.With(s.requirePerm("settings.write")).Get("/settings/infra", s.handleInfraStatus)
				r.With(s.requirePerm("settings.write")).Get("/settings/archive", s.handleGetArchiveSettings)
				r.With(s.requirePerm("settings.write")).Put("/settings/archive", s.handlePutArchiveSettings)
				r.With(s.requirePerm("settings.write")).Post("/settings/archive/sync", s.handleArchiveSync)
				r.With(s.requireAnyPerm("settings.write", "compliance.read")).Get("/settings/sbom", s.handleSBOM)

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
				r.With(s.requirePerm("users.read")).Get("/users/{id}/webauthn", s.handleListUserWebAuthn)
				r.With(s.requirePerm("users.read")).Get("/roles", s.handleListRoles)
				r.With(s.requirePerm("users.read")).Get("/groups", s.handleListGroups)
				r.With(s.requirePerm("users.read")).Get("/groups/{id}", s.handleGetGroup)
				r.With(s.requirePerm("users.write")).Post("/groups", s.handleCreateGroup)
				r.With(s.requirePerm("users.write")).Put("/groups/{id}", s.handleUpdateGroup)
				r.With(s.requirePerm("users.write")).Delete("/groups/{id}", s.handleDeleteGroup)
				r.With(s.requirePerm("audit.read")).Get("/audit-events/verify", s.handleVerifyAudit)
				r.With(s.requirePerm("audit.read")).Get("/audit-events/batches", s.handleListAuditBatches)
				r.With(s.requirePerm("audit.read")).Post("/audit-events/seal", s.handleSealAudit)
				r.With(s.requirePerm("audit.read")).Get("/audit-events", s.handleListAudit)
				r.With(s.requirePerm("audit.read")).Get("/analytics/overview", s.handleAnalyticsOverview)
				r.With(s.requirePerm("audit.read")).Get("/analytics/slo", s.handleAnalyticsSLO)

				r.With(s.requirePerm("compliance.read")).Get("/compliance/status", s.handleComplianceStatus)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/report", s.handleComplianceReport)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/packs", s.handleListCompliancePacks)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/packs/{id}/apply", s.handleApplyCompliancePack)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/retention", s.handleGetRetention)
				r.With(s.requirePerm("compliance.write")).Put("/compliance/retention", s.handlePutRetention)
				r.With(s.requirePerm("compliance.read")).Get("/compliance/legal-holds", s.handleListLegalHolds)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/legal-holds", s.handleCreateLegalHold)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/legal-holds/{id}/release", s.handleReleaseLegalHold)
				r.With(s.requirePerm("compliance.write")).Post("/compliance/purge", s.handleCompliancePurge)

				r.With(s.requirePerm("compliance.read")).Get("/dr/status", s.handleDRStatus)
				r.With(s.requirePerm("compliance.read")).Get("/geo/status", s.handleGeoStatus)
				r.With(s.requirePerm("compliance.read")).Get("/geo/recordings", s.handleGeoRecordings)
				r.With(s.requirePerm("compliance.write")).Post("/geo/recordings/sync", s.handleGeoRecordingsSync)
				r.With(s.requirePerm("compliance.read")).Get("/geo/promote/plan", s.handleGeoPromotePlan)
				r.With(s.requirePerm("compliance.read")).Get("/geo/witness", s.handleGeoWitness)
				r.With(s.requirePerm("compliance.read")).Get("/geo/drill", s.handleGeoDrill)
				r.With(s.requirePerm("compliance.write")).Post("/geo/drill", s.handleGeoDrill)
				r.With(s.requirePerm("compliance.read")).Get("/dr/settings", s.handleGetDRSettings)
				r.With(s.requirePerm("compliance.write")).Put("/dr/settings", s.handlePutDRSettings)
				r.With(s.requirePerm("compliance.write")).Post("/dr/backup", s.handleDRBackup)
				r.With(s.requirePerm("compliance.write")).Post("/dr/drill", s.handleDRDrill)

				r.With(s.requirePerm("apps.read")).Get("/assets/{id}/app", s.handleGetAppIntegration)
				r.With(s.requirePerm("apps.write")).Put("/assets/{id}/app", s.handlePutAppIntegration)
				r.With(s.requirePerm("sessions.connect")).Post("/assets/{id}/app/access", s.handleAppAccess)
				r.With(s.requirePerm("sessions.connect")).Post("/assets/{id}/k8s/access", s.handleK8sAccess)
				r.With(s.requirePerm("sessions.connect")).Post("/k8s/leases/{leaseId}/consume", s.handleConsumeK8sLease)

				r.With(s.requirePerm("assets.read")).Get("/assets", s.handleListAssets)
				r.With(s.requirePerm("assets.write")).Post("/assets", s.handleCreateAsset)
				r.With(s.requirePerm("assets.read")).Get("/license", s.handleGetLicense)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}", s.handleGetAsset)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}/citrix/resources", s.handleCitrixSFResources)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}/citrix/discovery", s.handleCitrixSFDiscovery)
				r.With(s.requirePerm("assets.read")).Get("/citrix/hdx/health", s.handleCitrixHDXHealth)
				r.With(s.requirePerm("sessions.write")).Post("/sessions/{id}/citrix/hdx/sync", s.handleCitrixHDXSync)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/citrix/sta/probe", s.handleCitrixSTAProbe)
				r.With(s.requirePerm("assets.write")).Patch("/assets/{id}", s.handleUpdateAsset)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}", s.handleDeleteAsset)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/firewall-applied", s.handleMarkFirewallApplied)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}/host-key", s.handleClearAssetHostKey)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts", s.handleCreateAccount)
				r.With(s.requirePerm("assets.write")).Patch("/assets/{id}/accounts/{accountId}", s.handleUpdateAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/rotate", s.handleRotateAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/checkout", s.handleCheckoutAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/checkin", s.handleCheckinAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/force-checkin", s.handleForceCheckinAccount)
				r.With(s.requirePerm("assets.write")).Post("/assets/{id}/accounts/{accountId}/reveal", s.handleRevealAccount)
				r.With(s.requirePerm("assets.write")).Delete("/assets/{id}/accounts/{accountId}", s.handleDeleteAccount)
				r.With(s.requirePerm("assets.read")).Get("/password-sets", s.handleListPasswordSets)
				r.With(s.requirePerm("assets.write")).Post("/password-sets", s.handleCreatePasswordSet)
				r.With(s.requirePerm("assets.read")).Get("/password-sets/{id}", s.handleGetPasswordSet)
				r.With(s.requirePerm("assets.write")).Patch("/password-sets/{id}", s.handleUpdatePasswordSet)
				r.With(s.requirePerm("assets.write")).Delete("/password-sets/{id}", s.handleDeletePasswordSet)
				r.With(s.requirePerm("assets.write")).Post("/password-sets/{id}/rotate", s.handleRotatePasswordSet)
				r.With(s.requirePerm("assets.write")).Get("/secret-checkouts", s.handleListCheckoutRequests)
				r.With(s.requirePerm("assets.write")).Post("/secret-checkouts/{id}/approve", s.handleApproveCheckoutRequest)
				r.With(s.requirePerm("assets.write")).Post("/secret-checkouts/{id}/deny", s.handleDenyCheckoutRequest)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}/acl", s.handleListACL)
				r.With(s.requirePerm("assets.acl")).Post("/assets/{id}/acl", s.handleCreateACL)
				r.With(s.requirePerm("assets.read")).Get("/assets/{id}/acl/{bindingId}", s.handleGetACL)
				r.With(s.requirePerm("assets.acl")).Put("/assets/{id}/acl/{bindingId}", s.handleUpdateACL)
				r.With(s.requirePerm("assets.acl")).Delete("/assets/{id}/acl/{bindingId}", s.handleDeleteACL)
				r.With(s.requirePerm("assets.read")).Get("/acl/tags", s.handleListTagACL)
				r.With(s.requirePerm("assets.acl")).Post("/acl/tags", s.handleCreateTagACL)

				r.With(s.requirePerm("jea.read")).Get("/jea/packs", s.handleListCommandPacks)
				r.With(s.requirePerm("jea.read")).Post("/jea/command-preview", s.handleCommandPreview)
				r.With(s.requirePerm("jea.read")).Get("/jea/packs/{id}", s.handleGetCommandPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/packs", s.handleCreateCommandPack)
				r.With(s.requirePerm("jea.write")).Put("/jea/packs/{id}", s.handleUpdateCommandPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/packs/{id}/import", s.handleImportCommandPack)
				r.With(s.requirePerm("jea.write")).Delete("/jea/packs/{id}", s.handleDeleteCommandPack)
				r.With(s.requirePerm("jea.read")).Get("/jea/sql-packs", s.handleListSQLPacks)
				r.With(s.requirePerm("jea.read")).Get("/jea/sql-packs/{id}", s.handleGetSQLPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/sql-packs", s.handleCreateSQLPack)
				r.With(s.requirePerm("jea.write")).Put("/jea/sql-packs/{id}", s.handleUpdateSQLPack)
				r.With(s.requirePerm("jea.write")).Delete("/jea/sql-packs/{id}", s.handleDeleteSQLPack)
				r.With(s.requirePerm("jea.read")).Get("/jea/http-packs", s.handleListHTTPPacks)
				r.With(s.requirePerm("jea.read")).Get("/jea/http-packs/{id}", s.handleGetHTTPPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/http-packs", s.handleCreateHTTPPack)
				r.With(s.requirePerm("jea.write")).Put("/jea/http-packs/{id}", s.handleUpdateHTTPPack)
				r.With(s.requirePerm("jea.write")).Delete("/jea/http-packs/{id}", s.handleDeleteHTTPPack)
				r.With(s.requirePerm("jea.read")).Post("/jea/app-object-preview", s.handleAppObjectPreview)
				r.With(s.requirePerm("jea.read")).Get("/jea/app-object-packs", s.handleListAppObjectPacks)
				r.With(s.requirePerm("jea.read")).Get("/jea/app-object-packs/{id}", s.handleGetAppObjectPack)
				r.With(s.requirePerm("jea.write")).Post("/jea/app-object-packs", s.handleCreateAppObjectPack)
				r.With(s.requirePerm("jea.write")).Put("/jea/app-object-packs/{id}", s.handleUpdateAppObjectPack)
				r.With(s.requirePerm("jea.write")).Delete("/jea/app-object-packs/{id}", s.handleDeleteAppObjectPack)
				r.With(s.requirePerm("jea.read")).Get("/jea/access-policies", s.handleListAccessPolicies)
				r.With(s.requirePerm("jea.read")).Get("/jea/access-policies/{id}", s.handleGetAccessPolicy)
				r.With(s.requirePerm("jea.write")).Post("/jea/access-policies", s.handleCreateAccessPolicy)
				r.With(s.requirePerm("jea.write")).Put("/jea/access-policies/{id}", s.handleUpdateAccessPolicy)
				r.With(s.requirePerm("jea.write")).Delete("/jea/access-policies/{id}", s.handleDeleteAccessPolicy)

				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/scenarios", s.handleListAttackScenarios)
				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/runs", s.handleListAttackRuns)
				r.With(s.requirePerm("attacksim.read")).Get("/attack-sim/runs/{id}", s.handleGetAttackRun)
				r.With(s.requirePerm("attacksim.write")).Post("/attack-sim/runs", s.handleStartAttackRun)

				r.With(s.requirePerm("access.request")).Post("/assets/{id}/access-requests", s.handleCreateAccessRequest)
				r.With(s.requireAnyPerm("access.request", "access.approve", "access.approve.security")).Get("/access-requests", s.handleListAccessRequests)
				r.With(s.requireAnyPerm("access.request", "access.approve", "access.approve.security")).Get("/access-requests/summary", s.handleAccessRequestsSummary)
				r.With(s.requireAnyPerm("access.approve", "access.approve.security")).Post("/access-requests/{id}/approve", s.handleApproveAccessRequest)
				r.With(s.requireAnyPerm("access.approve", "access.approve.security")).Post("/access-requests/{id}/deny", s.handleDenyAccessRequest)
				r.With(s.requireAnyPerm("access.approve", "access.approve.security")).Get("/op-approvals", s.handleListOpApprovals)
				r.With(s.requireAnyPerm("access.approve", "access.approve.security")).Post("/op-approvals/{id}/approve", s.handleApproveOp)
				r.With(s.requireAnyPerm("access.approve", "access.approve.security")).Post("/op-approvals/{id}/deny", s.handleDenyOp)
				r.With(s.requirePerm("access.request")).Post("/access-requests/{id}/cancel", s.handleCancelAccessRequest)
				r.With(s.requirePerm("access.breakglass")).Post("/assets/{id}/break-glass", s.handleOpenBreakGlass)
				r.With(s.requirePerm("access.breakglass")).Get("/break-glass", s.handleListBreakGlass)

				r.With(s.requirePerm("sessions.connect")).Post("/sessions", s.handleCreateSession)
				r.Post("/sessions/{id}/end", s.handleEndSession)
				r.With(s.requirePerm("sessions.supervise")).Post("/sessions/{id}/supervisor/approve", s.handleApproveSupervisor)
				r.With(s.requirePerm("sessions.supervise")).Post("/sessions/{id}/supervisor/deny", s.handleDenySupervisor)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/op-stepup", s.handleGetOpStepUp)
				r.With(s.requirePerm("sessions.read")).Get("/sessions", s.handleListSessions)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/events", s.handleSearchSessionEvents)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/timeline", s.handleSessionTimeline)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/rdp.rdp", s.handleDownloadRDP)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}", s.handleGetSession)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/kubeconfig", s.handleGetKubeconfig)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/k8s/catalog", s.handleK8sCatalog)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/k8s/namespaces", s.handleK8sNamespaces)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/k8s/list", s.handleK8sList)
				r.With(s.requirePerm("sessions.connect")).Get("/sessions/{id}/k8s/get", s.handleK8sGet)
				r.With(s.requirePerm("sessions.connect")).Post("/sessions/{id}/k8s/apply", s.handleK8sApply)
				r.With(s.requirePerm("sessions.connect")).Put("/sessions/{id}/k8s/object", s.handleK8sReplace)
				r.With(s.requirePerm("sessions.connect")).Post("/sessions/{id}/k8s/delete", s.handleK8sDelete)
				r.With(s.requirePerm("sessions.connect")).Post("/sessions/{id}/k8s/exec", s.handleK8sExecOnce)
				r.With(s.requirePerm("sessions.connect")).Post("/sessions/{id}/k8s/portforward", s.handleK8sPortForwardHTTP)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}/recording", s.handleGetRecording)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}/recording.mp4", s.handleGetRecordingMP4)
				r.With(s.requirePerm("sessions.files.read")).Get("/sessions/{id}/files", s.handleListSessionFiles)
				r.With(s.requirePerm("sessions.files.read")).Get("/sessions/{id}/files/{fileId}", s.handleGetSessionFile)
				r.With(s.requirePerm("sessions.read")).Get("/sessions/{id}/transcript", s.handleGetTranscript)
				r.With(s.requirePerm("sessions.read")).Post("/sessions/{id}/transcript", s.handleIndexTranscript)
			})
		})
	})

	return r
}

func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	if s.health != nil {
		s.health.ServeLive(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.health != nil {
		s.health.ServeReady(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type ctxKey int

const sessKey ctxKey = 1

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == s.cfg.CORSOrigin || s.cfg.CORSOrigin == "*" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
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
		next.ServeHTTP(w, s.bindSession(r, sess))
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
	return s.requireAnyPerm(perm)
}

func (s *Server) requireAnyPerm(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mustSess(r)
			for _, p := range perms {
				if rbac.HasPermission(sess.Permissions, p) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeErr(w, http.StatusForbidden, "forbidden")
		})
	}
}

func mustSess(r *http.Request) session.Session {
	return r.Context().Value(sessKey).(session.Session)
}

func (s *Server) bindSession(r *http.Request, sess session.Session) *http.Request {
	ctx := context.WithValue(r.Context(), sessKey, sess)
	ctx = policy.WithDevices(ctx, s.clientDevices(r, sess.Devices...))
	return r.WithContext(ctx)
}

func (s *Server) clientDevices(r *http.Request, extra ...string) []string {
	return device.FilterTrustDomain(device.Merge(device.FromTLS(r.TLS), extra), s.cfg.SPIFFETrustDomain)
}

func (s *Server) stampDevice(r *http.Request, token string, extra ...string) {
	if token == "" {
		return
	}
	sess, err := s.sessions.Get(r.Context(), token)
	if err != nil {
		return
	}
	sess.Devices = s.clientDevices(r, extra...)
	_ = s.sessions.Update(r.Context(), token, sess)
}

func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, token string, extra ...string) error {
	if token == "" {
		return nil
	}
	if err := s.setSessionCookies(w, token); err != nil {
		return err
	}
	s.stampDevice(r, token, extra...)
	return nil
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

func (s *Server) clientIP(r *http.Request) string {
	return geoip.RequestClientIP(r, s.cfg.TrustedProxies)
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
	res, err := s.auth.Login(r.Context(), body.Username, body.Password, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if res.SessionToken != "" {
		if err := s.completeLogin(w, r, res.SessionToken); err != nil {
			writeErr(w, http.StatusInternalServerError, "session error")
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLoginCert(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeErr(w, http.StatusUnauthorized, "client certificate required")
		return
	}
	res, err := s.auth.LoginCert(r.Context(), r.TLS.PeerCertificates[0], s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if res.SessionToken != "" {
		if err := s.completeLogin(w, r, res.SessionToken); err != nil {
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
	res, err := s.auth.VerifyMFA(r.Context(), body.ChallengeToken, body.Code, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.completeLogin(w, r, res.SessionToken); err != nil {
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
	_ = s.auth.Logout(r.Context(), token, &sess.UserID, s.clientIP(r), r.UserAgent())
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
	if err := s.auth.ConfirmMFASetup(r.Context(), sess.UserID, body.Code, s.clientIP(r), r.UserAgent()); err != nil {
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
	res, err := s.users.Create(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
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
	u, err := s.users.Update(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
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
	temp, err := s.users.ResetPassword(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
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
	if err := s.users.ResetMFA(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
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
	key, err := s.users.AddSSHKey(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
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
	if err := s.users.DeleteSSHKey(r.Context(), sess.UserID, id, keyID, s.clientIP(r), r.UserAgent()); err != nil {
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

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := s.audit.Verify(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListAuditBatches(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	list, err := s.audit.ListBatches(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": list})
}

func (s *Server) handleSealAudit(w http.ResponseWriter, r *http.Request) {
	n, err := s.audit.SealOnce(r.Context(), true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sealed": n})
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	list, err := s.assets.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": list})
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	n, err := s.assets.CountActive(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.license.Evaluate(n, time.Now()))
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in assets.CreateAssetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	n, err := s.assets.CountActive(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.license.AllowCreate(n, time.Now()); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	a, err := s.assets.Create(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
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
	a, err := s.assets.Update(r.Context(), sess.UserID, id, in, s.clientIP(r), r.UserAgent())
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
	a, err := s.assets.ClearHostKey(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent())
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
	if err := s.assets.Delete(r.Context(), sess.UserID, id, s.clientIP(r), r.UserAgent()); err != nil {
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
	acc, err := s.assets.CreateAccount(r.Context(), sess.UserID, assetID, in, s.clientIP(r), r.UserAgent())
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
	acc, err := s.assets.UpdateAccount(r.Context(), sess.UserID, accountID, in, s.clientIP(r), r.UserAgent())
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
	res, err := s.assets.RotateSecret(r.Context(), sess.UserID, assetID, accountID, in, s.clientIP(r), r.UserAgent())
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
	if err := s.assets.DeleteAccount(r.Context(), sess.UserID, accountID, s.clientIP(r), r.UserAgent()); err != nil {
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

func (s *Server) handleListTagACL(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListTagBindings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": list})
}

func (s *Server) handleCreateTagACL(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.CreateBindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, err := s.policy.CreateTag(r.Context(), sess.UserID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) handleGetACL(w http.ResponseWriter, r *http.Request) {
	bindingID, err := uuid.Parse(chi.URLParam(r, "bindingId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid binding id")
		return
	}
	b, err := s.policy.GetRaw(r.Context(), bindingID)
	if err != nil {
		if policy.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, b)
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
	b, err := s.policy.Create(r.Context(), sess.UserID, assetID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) handleUpdateACL(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	bindingID, err := uuid.Parse(chi.URLParam(r, "bindingId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid binding id")
		return
	}
	var in policy.CreateBindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, err := s.policy.Update(r.Context(), sess.UserID, bindingID, in, s.clientIP(r), r.UserAgent())
	if err != nil {
		if policy.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleDeleteACL(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	bindingID, err := uuid.Parse(chi.URLParam(r, "bindingId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid binding id")
		return
	}
	if err := s.policy.Delete(r.Context(), sess.UserID, bindingID, s.clientIP(r), r.UserAgent()); err != nil {
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
	writeJSON(w, code, map[string]string{"error": msg, "code": errSlug(msg)})
}

func errSlug(msg string) string {
	s := strings.ToLower(strings.TrimSpace(msg))
	var b strings.Builder
	prevUS := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			prevUS = false
			continue
		}
		if !prevUS && b.Len() > 0 {
			b.WriteByte('_')
			prevUS = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		return "error"
	}
	return out
}
