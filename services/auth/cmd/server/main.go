package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/adjit"
	"github.com/keeppam/auth/internal/analytics"
	"github.com/keeppam/auth/internal/appaccess"
	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/attacksim"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/auth"
	"github.com/keeppam/auth/internal/castindex"
	"github.com/keeppam/auth/internal/compliance"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/dbephemeral"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/discovery"
	"github.com/keeppam/auth/internal/dr"
	"github.com/keeppam/auth/internal/filexfer"
	"github.com/keeppam/auth/internal/fips"
	"github.com/keeppam/auth/internal/firewall"
	"github.com/keeppam/auth/internal/geo"
	"github.com/keeppam/auth/internal/geoip"
	"github.com/keeppam/auth/internal/health"
	httpapi "github.com/keeppam/auth/internal/http"
	"github.com/keeppam/auth/internal/itsm"
	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/license"
	"github.com/keeppam/auth/internal/migrate"
	"github.com/keeppam/auth/internal/notify"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/opapprove"
	"github.com/keeppam/auth/internal/pades"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/recarch"
	"github.com/keeppam/auth/internal/recstore"
	"github.com/keeppam/auth/internal/rdpgw"
	"github.com/keeppam/auth/internal/scim"
	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/settings"
	"github.com/keeppam/auth/internal/siem"
	"github.com/keeppam/auth/internal/spiffe"
	"github.com/keeppam/auth/internal/sshca"
	"github.com/keeppam/auth/internal/sshgw"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/telnetgw"
	"github.com/keeppam/auth/internal/tn3270gw"
	"github.com/keeppam/auth/internal/citrix/hdx"
	"github.com/keeppam/auth/internal/citrixgw"
	"github.com/keeppam/auth/internal/users"
)

type mainHDXSink struct{ sess *sessionsvc.Service }

func (m mainHDXSink) GetRecordingPath(ctx context.Context, sessionID uuid.UUID) (string, time.Time, error) {
	row, err := m.sess.Get(ctx, sessionID)
	if err != nil {
		return "", time.Time{}, err
	}
	base := row.CreatedAt
	if row.StartedAt != nil {
		base = *row.StartedAt
	}
	return row.RecordingPath, base, nil
}

func (m mainHDXSink) AddEventAt(ctx context.Context, sessionID uuid.UUID, ts time.Time, eventType string, payload map[string]any) error {
	return m.sess.AddEventAt(ctx, sessionID, ts, eventType, payload)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "readyz" {
		os.Exit(probeReadyz())
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	if err := fips.Enforce(cfg.FIPSRequired); err != nil {
		slog.Error("fips", "err", err)
		os.Exit(1)
	}
	mem := crypto.Harden()
	slog.Info("memory", "coredump", mem.CoreDump, "dumpable", mem.Dumpable)

	kp, err := crypto.NewKeyProviderFromEnv()
	if err != nil {
		slog.Error("key provider", "err", err)
		os.Exit(1)
	}
	key, err := kp.Load(context.Background())
	if err != nil {
		slog.Error("data key", "source", kp.Source(), "err", err)
		os.Exit(1)
	}
	cfg.DataKey = key
	cfg.DataKeySource = kp.Source()

	svcName := "keeppam-api"
	if cfg.Mode == "ssh" {
		svcName = "keeppam-ssh"
	}
	traceStop, err := obs.InitTracing(context.Background(), cfg.OTELEndpoint, svcName)
	if err != nil {
		slog.Error("tracing", "err", err)
		os.Exit(1)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceStop(c)
	}()
	if cfg.OTELEndpoint != "" {
		slog.Info("tracing otlp", "endpoint", obs.NormalizeOTLPEndpoint(cfg.OTELEndpoint), "via", obs.OTELVia(cfg.OTELEndpoint), "service", svcName)
	}

	recStore, err := recstore.NewFromEnv(cfg.RecordingsDir)
	if err != nil {
		slog.Error("recordings store", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	migDir := os.Getenv("KEEPPAM_MIGRATIONS_DIR")
	if migDir == "" {
		migDir = filepath.Join("migrations")
	}

	runHTTP := cfg.Mode == "all" || cfg.Mode == "api"
	runSSH := cfg.Mode == "all" || cfg.Mode == "ssh"
	if cfg.SSHAddr == "" || cfg.SSHAddr == "off" {
		runSSH = false
	}

	if runHTTP {
		if err := migrate.Up(ctx, cfg.DatabaseURL, migDir); err != nil {
			slog.Error("migrate", "err", err)
			os.Exit(1)
		}
	}

	db, err := store.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	sessions, err := session.Connect(cfg.RedisURL)
	if err != nil {
		slog.Error("redis", "err", err)
		os.Exit(1)
	}
	defer sessions.Close()

	env, err := crypto.NewEnvelope(cfg.DataKey)
	if err != nil {
		slog.Error("envelope", "err", err)
		os.Exit(1)
	}
	crypto.Wipe(cfg.DataKey)
	cfg.DataKey = nil
	mem = crypto.LastMemStatus()
	slog.Info("memory", "data_key_mlock", mem.DataKeyMlock, "coredump", mem.CoreDump)

	life := health.New()
	life.SetCheck(func(ctx context.Context) error {
		if err := db.Pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		if err := sessions.Redis().Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		gcfg := geo.Config{
			SiteID: cfg.SiteID, Role: cfg.SiteRole, PeerURL: cfg.SitePeerURL,
			ReplicaDSN: cfg.SiteReplicaDSN, MaxLagSeconds: cfg.SiteMaxLagSeconds,
		}
		if gcfg.IsStandby() && (gcfg.MaxLagSeconds > 0 || gcfg.ReplicaDSN != "") {
			st := geo.Probe(ctx, gcfg)
			if st.ReplicaProbe == "error" {
				return fmt.Errorf("geo replica: %s", st.ReplicaError)
			}
			if st.LagOK != nil && !*st.LagOK {
				return fmt.Errorf("geo lag %.1fs exceeds max %ds", *st.LagSeconds, gcfg.MaxLagSeconds)
			}
		}
		return nil
	})

	auditSvc := audit.New(db)
	auditSvc.SetMAC(env)
	archSvc := recarch.New(db, auditSvc, env, recStore)
	recStore = recarch.Wrap(recStore, archSvc)
	settingsSvc := settings.New(db, auditSvc, env)
	siemSvc := siem.New(db, auditSvc, env)
	itsmSvc := itsm.New(db, auditSvc, env, sessions.Redis())
	firewallSvc := firewall.New(db, auditSvc, env)
	notifySvc := notify.New(db, auditSvc, env)
	authSvc := auth.New(db, sessions, auditSvc, env, cfg, settingsSvc)
	usersSvc := users.New(db, auditSvc)
	scimSvc := scim.New(db, usersSvc, auditSvc)
	assetsSvc := assets.New(db, env, auditSvc)
	licFile, licErr := license.Load(cfg.LicenseFile)
	if licErr != nil {
		slog.Warn("license load", "err", licErr)
		licFile = license.DefaultFile()
	}
	assetsSvc.SetAssetQuota(func(ctx context.Context) error {
		n, err := assetsSvc.CountActive(ctx)
		if err != nil {
			return err
		}
		return licFile.AllowCreate(n, time.Now())
	})
	slog.Info("license", "max_assets", licFile.MaxAssets, "ha", licFile.HA, "source", licFile.Source)
	sshCASvc := sshca.New(db, env, auditSvc)
	assetsSvc.SetSSHCA(sshCASvc)
	policySvc := policy.New(db, auditSvc)
	policySvc.SetGeo(geoip.New(cfg.GeoIPDB))
	if g := policySvc.Geo(); g != nil && g.Loaded() {
		slog.Info("geoip", "path", g.Path(), "type", g.DatabaseType(), "nodes", g.NodeCount())
	} else if cfg.GeoIPDB != "" {
		slog.Warn("geoip not loaded", "path", cfg.GeoIPDB)
	}
	opaEng, err := policy.LoadOPA(cfg.OPAPolicy)
	if err != nil {
		slog.Error("opa policy", "err", err)
		os.Exit(1)
	}
	policySvc.SetOPA(opaEng)
	if cfg.OPAPolicy != "" {
		slog.Info("opa policy", "path", cfg.OPAPolicy, "package", opaEng.Package())
	}
	sessSvc := sessionsvc.New(db, auditSvc, cfg.RecordingsDir)
	sessSvc.SetRecordingStore(recStore)
	filesSvc := filexfer.New(db, sessSvc, recStore, cfg.RecordingsDir)
	castIdx := castindex.New(sessSvc, recStore, cfg.GuacencURL)
	castIdx.SetUEBAHook(func(ctx context.Context, row sessionsvc.Session, payload map[string]any) {
		notifySvc.OnUEBAAnomaly(ctx, row, payload)
	})
	live := sessionsvc.NewLiveHub(sessions.Redis())
	var rdpBroker *rdpgw.Broker
	discoverySvc := discovery.New(db, auditSvc, assetsSvc)
	analyticsSvc := analytics.New(db)
	appsSvc := appaccess.New(db, auditSvc, env, assetsSvc, policySvc, sessions.Redis())
	complianceSvc := compliance.New(db, auditSvc, cfg.RecordingsDir, recStore, cfg.DataKeySource)
	if cfg.PDFCertFile != "" {
		sig, err := pades.Load(cfg.PDFCertFile, cfg.PDFKeyFile)
		if err != nil {
			slog.Error("pades signer", "err", err)
			os.Exit(1)
		}
		sig.TSAURL = cfg.PDFTSAURL
		sig.LTV = cfg.PDFLTV
		sig.LTVDir = cfg.PDFLTVDir
		sig.LTVFetch = cfg.PDFLTVFetch
		sig.LTA = cfg.PDFLTA
		complianceSvc.SetPDFSigner(sig)
		slog.Info("pades signer", "cn", sig.CN(), "profile", sig.Profile(), "tsa", cfg.PDFTSAURL != "", "ltv", cfg.PDFLTV, "lta", cfg.PDFLTA)
	}
	drSvc := dr.New(db, auditSvc, cfg.DatabaseURL, cfg.RecordingsDir)
	dbEphSvc := dbephemeral.New(db, env, assetsSvc, auditSvc, sessSvc)
	opsSvc := opapprove.New(db, sessions.Redis(), auditSvc)
	opsSvc.OnCreated = func(ctx context.Context, rec opapprove.Approval) {
		notifySvc.OnOpApproval(ctx, rec)
	}
	var k8sGw *k8sproxy.Gateway
	resolveDir := func(ctx context.Context) (adjit.DirectoryConfig, error) {
		cfg, _, ldapEnc, err := settingsSvc.Get(ctx)
		if err != nil {
			return adjit.DirectoryConfig{}, err
		}
		pass, err := settingsSvc.DecryptSecret(ldapEnc)
		if err != nil {
			return adjit.DirectoryConfig{}, err
		}
		return adjit.DirectoryFromAuthSettings(cfg, pass), nil
	}
	discoverySvc.SetDirectory(resolveDir)
	adJit := adjit.New(db, assetsSvc, sessSvc, auditSvc, resolveDir)
	assetsSvc.SetLDAPPasswordChanger(adJit)
	hdxClient := hdx.NewClient(cfg.CitrixHDXPluginURL)
	sessSvc.SetStartHook(adJit.OnSessionStart)
	sessSvc.SetEndHook(func(ctx context.Context, id uuid.UUID, protocol string) {
		live.Fanout(ctx, id, "end", "")
		live.Clear(ctx, id)
		opsSvc.ExpireSession(ctx, id)
		authSvc.ClearOpStepUp(ctx, id)
		if protocol == "postgres" || protocol == "mysql" {
			dbEphSvc.Drop(ctx, id)
		}
		if protocol == "https" {
			appsSvc.IsolateStop(ctx, id)
		}
		if protocol == "kubectl" {
			k8sproxy.ClearToken(ctx, sessions.Redis(), id)
			if k8sGw != nil {
				k8sGw.DropSession(id)
			}
		}
		adJit.OnSessionEnd(ctx, id)
		if rdpBroker != nil {
			rdpBroker.Stop(id)
		}
		if protocol == "citrix" {
			hdx.Finalize(ctx, sessions.Redis(), hdxClient, mainHDXSink{sess: sessSvc}, id, cfg.SessionTTL)
		}
		if row, err := sessSvc.Get(ctx, id); err == nil {
			if err := assetsSvc.MaybeRotateAfterSession(ctx, row.AccountID); err != nil {
				slog.Warn("rotate after session", "session", id.String(), "account", row.AccountID.String(), "err", err)
			}
		}
		if protocol == "ssh" || protocol == "rdp" || protocol == "vnc" || protocol == "https" || protocol == "citrix" {
			castIdx.IndexAsync(id)
			if protocol == "rdp" || protocol == "vnc" || protocol == "https" || protocol == "citrix" {
				castIdx.IndexOCRAsync(id)
			}
		}
	})
	ensureEph := func(ctx context.Context, sessionID uuid.UUID, vault assets.TargetCreds, privilege string) (assets.TargetCreds, string, error) {
		creds, info, err := dbEphSvc.Ensure(ctx, sessionID, vault, privilege)
		return creds, info.RoleName, err
	}
	resolveSQLGuard := func(ctx context.Context, sessionID uuid.UUID) (*dbproxy.SQLGuard, error) {
		row, err := sessSvc.Get(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		var pack policy.SQLPack
		hasPack := false
		if row.SQLPolicyPackID != nil {
			if p, err := policySvc.GetSQLPack(ctx, *row.SQLPolicyPackID); err == nil {
				pack, hasPack = p, true
			}
		}
		p := pack
		hp := hasPack
		return &dbproxy.SQLGuard{
			Allow: func(stmt string) (bool, string) {
				if ok, reason := policy.AllowSQL(p, hp, stmt); !ok {
					return false, reason
				}
				ev, err := policySvc.CheckOpRisk(ctx, policy.AccessCheck{
					UserID: row.UserID, AssetID: row.AssetID, TicketID: row.TicketID,
					ClientIP: row.ClientIP, Operation: policy.SQLOperation(stmt), Snapshot: row.PolicySnapshot,
					StepUpVerified: authSvc.HasOpStepUp(ctx, sessionID, row.UserID),
				})
				if err == nil && !ev.OK {
					if ev.NeedsStepUp() {
						return false, ev.RiskDenyMessage() + "; confirm MFA in web SQL console"
					}
					return false, ev.DenyMessage()
				}
				return true, ""
			},
			Mask: func(cols []string, rows [][]string) ([]string, [][]string) {
				if !hp {
					return cols, rows
				}
				return policy.MaskSQLResult(p, cols, rows)
			},
			FilterRows: func(cols []string, rows [][]string) ([][]string, error) {
				dlp := row.PolicySnapshot.ContentDLP()
				out, deny, kinds := policy.ApplyContentDLPRows(dlp, rows)
				if deny {
					return rows, fmt.Errorf("%w: %s", dbproxy.ErrPIIContent, strings.Join(kinds, ","))
				}
				if len(kinds) > 0 {
					_ = sessSvc.AddEvent(ctx, sessionID, "dlp", map[string]any{
						"action": "mask", "kinds": kinds, "via": "wire",
					})
					_ = auditSvc.Record(ctx, &row.UserID, "session.dlp.masked", "session", sessionID.String(), "", "dbwire", map[string]any{
						"kinds": kinds,
					})
				}
				return out, nil
			},
			MaxRows: policy.SQLRowLimit(p, hp),
			DLPDeny: policy.SQLDLPDeny(p, hp),
		}, nil
	}
	attackSimSvc := attacksim.New(db, auditSvc, policySvc, cfg.HTTPAddr)

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	go live.Listen(runCtx)
	go auditSvc.RunSealer(runCtx)
	if runHTTP {
		go firewallSvc.RunProbeScheduler(runCtx)
	}

	if runHTTP {
		if err := authSvc.Bootstrap(ctx); err != nil {
			slog.Error("bootstrap", "err", err)
			os.Exit(1)
		}
	}

	var srv *http.Server
	if runHTTP {
		if cfg.K8sAPIAddr != "" && cfg.K8sAPIAddr != "off" {
			pub := cfg.K8sPublicURL
			if pub == "" {
				pub = k8sproxy.DefaultPublicURL(cfg.CORSOrigin, cfg.K8sAPIAddr)
			}
			cert, err := k8sproxy.LoadOrCreateTLS(cfg.K8sTLSCertFile, cfg.K8sTLSKeyFile, cfg.K8sTLSPath, pub)
			if err != nil {
				slog.Error("k8s tls", "err", err)
			} else {
				k8sGw = k8sproxy.New(cfg.K8sAPIAddr, pub, cert, sessions.Redis(), assetsSvc, sessSvc, auditSvc, live)
				k8sGw.SetPolicy(policySvc)
				k8sGw.SetOps(opsSvc)
				k8sGw.SetOpStepUp(authSvc.HasOpStepUp, func(ctx context.Context, row sessionsvc.Session, ev policy.AccessResult) error {
					if p, ok := authSvc.GetOpStepUpPending(ctx, row.ID); ok && p.ChallengeToken != "" {
						return nil
					}
					tok, methods, err := authSvc.BeginStepUp(ctx, row.UserID, row.Username, row.AssetID, row.ID)
					if err != nil {
						return err
					}
					factors := ev.RiskFactors
					if factors == nil {
						factors = []string{}
					}
					return authSvc.PutOpStepUpPending(ctx, row.ID, session.OpStepUpPending{
						ChallengeToken: tok, TOTP: methods.TOTP, WebAuthn: methods.WebAuthn,
						RiskScore: ev.RiskScore, MaxRisk: ev.MaxRisk, RiskFactors: factors, Operation: ev.Operation,
					})
				})
				k8sGw.SetTrustedProxies(cfg.TrustedProxies)
				k8sGw.SetRoles(func(ctx context.Context, userID uuid.UUID) []string {
					u, err := db.GetUserByID(ctx, userID)
					if err != nil {
						return nil
					}
					return u.Roles
				})
				k8sGw.SetGroups(func(ctx context.Context, userID uuid.UUID) []string {
					names, err := policySvc.EffectiveGroupNames(ctx, userID)
					if err != nil {
						return nil
					}
					return names
				})
				go func() {
					if err := k8sGw.ListenAndServe(runCtx); err != nil && err != http.ErrServerClosed {
						slog.Error("k8s api gateway", "err", err)
					}
				}()
			}
		}
		var rdpBrokerInit *rdpgw.Broker
		if cfg.RDPPublicHost != "" && cfg.RDPPublicHost != "off" {
			cert, key := cfg.RDPProxyCertFile, cfg.RDPProxyKeyFile
			if cert == "" {
				cert = cfg.TLSCertFile
			}
			if key == "" {
				key = cfg.TLSKeyFile
			}
			rdpBrokerInit = rdpgw.NewBroker(cfg.RDPPublicHost, cfg.RDPProxyBin, cert, key,
				filepath.Join(cfg.RecordingsDir, "rdp-proxy"), sessions.Redis(), assetsSvc, sessSvc)
			rdpBroker = rdpBrokerInit
			slog.Info("native RDP broker", "public_host", cfg.RDPPublicHost, "proxy_bin", cfg.RDPProxyBin != "" && cfg.RDPProxyBin != "off")
		}
		handler := httpapi.New(cfg, authSvc, usersSvc, assetsSvc, policySvc, sessSvc, auditSvc, sessions, live, settingsSvc, siemSvc, discoverySvc, analyticsSvc, appsSvc, complianceSvc, drSvc, dbEphSvc, attackSimSvc, sshCASvc, itsmSvc, notifySvc, k8sGw, opsSvc, scimSvc, firewallSvc, archSvc, filesSvc, life, rdpBroker, castIdx)
		srv = &http.Server{Addr: cfg.HTTPAddr, Handler: handler}
		go func() {
			if cfg.TLSEnabled() {
				tlsCfg, err := httpapi.BuildTLSConfig(cfg)
				if err != nil {
					slog.Error("tls", "err", err)
					os.Exit(1)
				}
				srv.TLSConfig = tlsCfg
				slog.Info("listening tls", "addr", cfg.HTTPAddr, "mode", cfg.Mode, "mtls", cfg.MTLSMode(),
					"data_key", cfg.DataKeySource, "recordings", recStore.Backend(),
					"spiffe_id", loadSPIFFEID(cfg), "spiffe_domain", cfg.SPIFFETrustDomain,
					"fips", fips.Backend())
				if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
					slog.Error("http", "err", err)
					os.Exit(1)
				}
				return
			}
			slog.Info("listening", "addr", cfg.HTTPAddr, "mode", cfg.Mode,
				"data_key", cfg.DataKeySource, "recordings", recStore.Backend(),
				"fips", fips.Backend())
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("http", "err", err)
				os.Exit(1)
			}
		}()
		go siemSvc.Run(runCtx)
		go discoverySvc.Run(runCtx)
		go complianceSvc.Run(runCtx)
		go archSvc.Run(runCtx)
		if cfg.PostgresWireAddr != "" && cfg.PostgresWireAddr != "off" {
			pgWire := dbproxy.NewWireGateway(cfg.PostgresWireAddr, "postgres", sessions.Redis(), assetsSvc, sessSvc, auditSvc, live, ensureEph, resolveSQLGuard)
			go func() {
				if err := pgWire.ListenAndServe(runCtx); err != nil {
					slog.Error("postgres wire", "err", err)
				}
			}()
		}
		if cfg.MySQLWireAddr != "" && cfg.MySQLWireAddr != "off" {
			myWire := dbproxy.NewWireGateway(cfg.MySQLWireAddr, "mysql", sessions.Redis(), assetsSvc, sessSvc, auditSvc, live, ensureEph, resolveSQLGuard)
			go func() {
				if err := myWire.ListenAndServe(runCtx); err != nil {
					slog.Error("mysql wire", "err", err)
				}
			}()
		}
		if cfg.MSSQLWireAddr != "" && cfg.MSSQLWireAddr != "off" {
			msWire := dbproxy.NewWireGateway(cfg.MSSQLWireAddr, "mssql", sessions.Redis(), assetsSvc, sessSvc, auditSvc, live, ensureEph, resolveSQLGuard)
			go func() {
				if err := msWire.ListenAndServe(runCtx); err != nil {
					slog.Error("mssql wire", "err", err)
				}
			}()
		}
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
					if n, err := sessSvc.CloseStale(runCtx, 2*time.Minute); err != nil {
						slog.Warn("session reaper", "err", err)
					} else if n > 0 {
						slog.Info("session reaper closed stale", "count", n)
					}
					if n, err := sessSvc.ExpireWaitingSupervisor(runCtx, 15*time.Minute); err != nil {
						slog.Warn("supervisor wait reaper", "err", err)
					} else if n > 0 {
						slog.Info("supervisor wait timed out", "count", n)
					}
					expired, err := policySvc.ExpirePending(runCtx, cfg.AccessRequestTTL)
					if err != nil {
						slog.Warn("access request reaper", "err", err)
					} else if expired > 0 {
						slog.Info("access request reaper expired", "count", expired)
					}
					if n, err := policySvc.CloseExpiredBreakGlass(runCtx); err != nil {
						slog.Warn("break-glass reaper", "err", err)
					} else if n > 0 {
						slog.Info("break-glass closed expired", "count", n)
					}
					if n, err := assetsSvc.ExpireCheckouts(runCtx); err != nil {
						slog.Warn("checkout reaper", "err", err)
					} else if n > 0 {
						slog.Info("checkout reaper expired", "count", n)
					}
					if n, err := assetsSvc.RunDueRotations(runCtx); err != nil {
						slog.Warn("scheduled rotation", "err", err)
					} else if n > 0 {
						slog.Info("scheduled rotation done", "count", n)
					}
					if n, err := assetsSvc.ReconcilePendingRotations(runCtx); err != nil {
						slog.Warn("rotation reconcile", "err", err)
					} else if n > 0 {
						slog.Info("rotation reconcile done", "count", n)
					}
				}
			}
		}()
	}

	var sshGw *sshgw.Gateway
	if runSSH {
		sshGw = sshgw.New(cfg.SSHAddr, cfg.SSHHostKeyPath, authSvc, assetsSvc, policySvc, sessSvc, auditSvc, live, itsmSvc, opsSvc, firewallSvc, filesSvc)
		sshGw.SetSessionFence(func() error {
			return geo.FenceError(geo.Config{SiteID: cfg.SiteID, Role: cfg.SiteRole})
		})
		go func() {
			slog.Info("ssh worker starting", "addr", cfg.SSHAddr, "mode", cfg.Mode, "recordings", recStore.Backend())
			if err := sshGw.ListenAndServe(); err != nil {
				slog.Error("ssh gateway", "err", err)
				os.Exit(1)
			}
		}()
	}

	if (cfg.Mode == "all" || cfg.Mode == "ssh") && cfg.TelnetAddr != "" && cfg.TelnetAddr != "off" {
		tnGw := telnetgw.New(cfg.TelnetAddr, sessions.Redis(), assetsSvc, sessSvc, auditSvc)
		go func() {
			slog.Info("telnet worker starting", "addr", cfg.TelnetAddr, "mode", cfg.Mode)
			if err := tnGw.ListenAndServe(runCtx); err != nil {
				slog.Error("telnet gateway", "err", err)
				os.Exit(1)
			}
		}()
	}

	if (cfg.Mode == "all" || cfg.Mode == "ssh") && cfg.TN3270Addr != "" && cfg.TN3270Addr != "off" {
		t3Gw := tn3270gw.New(cfg.TN3270Addr, sessions.Redis(), assetsSvc, sessSvc, auditSvc)
		go func() {
			slog.Info("tn3270 worker starting", "addr", cfg.TN3270Addr, "mode", cfg.Mode)
			if err := t3Gw.ListenAndServe(runCtx); err != nil {
				slog.Error("tn3270 gateway", "err", err)
				os.Exit(1)
			}
		}()
	}

	if (cfg.Mode == "all" || cfg.Mode == "ssh") && cfg.CitrixSocksAddr != "" && cfg.CitrixSocksAddr != "off" {
		cxGw := citrixgw.New(cfg.CitrixSocksAddr, sessions.Redis(), assetsSvc, sessSvc, auditSvc)
		go func() {
			slog.Info("citrix socks starting", "addr", cfg.CitrixSocksAddr, "mode", cfg.Mode)
			if err := cxGw.ListenAndServe(runCtx); err != nil {
				slog.Error("citrix socks", "err", err)
				os.Exit(1)
			}
		}()
	}

	if runSSH && !runHTTP {
		hs := &http.Server{Addr: cfg.HTTPAddr, Handler: life.Handler()}
		go func() {
			slog.Info("ssh health listening", "addr", cfg.HTTPAddr)
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("ssh health", "err", err)
			}
		}()
		defer func() {
			c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = hs.Shutdown(c)
		}()
	}

	if !runHTTP && !runSSH {
		slog.Error("nothing to run", "mode", cfg.Mode)
		os.Exit(1)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	slog.Info("shutdown", "drain", cfg.DrainTimeout.String())
	life.SetDraining(true)
	runCancel()
	drainCtx, drainCancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	defer drainCancel()
	if sshGw != nil {
		sshGw.Drain(drainCtx)
	}
	if srv != nil {
		_ = srv.Shutdown(drainCtx)
	}
}

func loadSPIFFEID(cfg config.Config) string {
	if cfg.SPIFFESVIDFile == "" {
		return ""
	}
	id, err := spiffe.LoadPEM(cfg.SPIFFESVIDFile, "")
	if err != nil || len(id.IDs) == 0 {
		return ""
	}
	return id.IDs[0]
}

func probeReadyz() int {
	addr := os.Getenv("KEEPPAM_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/readyz", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
