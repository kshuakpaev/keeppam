package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr               string
	DatabaseURL            string
	RedisURL               string
	DataKey                []byte
	DataKeySource          string
	BootstrapAdminPassword string
	SessionTTL             time.Duration
	ChallengeTTL           time.Duration
	CookieSecure           bool
	CookieDomain           string
	CORSOrigin             string
	MaxFailedLogins        int
	LockoutDuration        time.Duration
	RecordingsDir          string
	RecordingsBackend      string
	S3Endpoint             string
	S3Bucket               string
	S3Region               string
	S3Prefix               string
	S3ObjectLockMode       string
	S3ObjectLockDays       int
	SSHAddr                string
	SSHHostKeyPath         string
	TelnetAddr             string // native telnet gateway; empty/off = disabled
	TN3270Addr             string // native TN3270 gateway; empty/off = disabled
	CitrixSocksAddr        string // SOCKS5 for Citrix ICA; empty/off = disabled
	CitrixPublicHost       string // hostname in .ica ProxyHost; empty = localhost
	CitrixHDXPluginURL     string // OEM HDX terminate plugin HTTP base; empty/off = disabled
	CitrixHDXCallbackBase  string // public base for plugin ingest callback; empty = CORSOrigin
	Mode                   string // all | api | ssh
	GuacdAddr              string
	GuacencURL             string
	AccessRequestTTL       time.Duration
	PostgresWireAddr       string
	MySQLWireAddr          string
	MSSQLWireAddr          string
	K8sAPIAddr             string
	K8sTLSCertFile         string
	K8sTLSKeyFile          string
	K8sTLSPath             string
	K8sPublicURL           string
	TLSCertFile            string
	TLSKeyFile             string
	TLSClientCAFile        string
	TLSRequireClientCert   bool
	SPIFFETrustDomain      string
	SPIFFESVIDFile         string
	SPIFFESVIDKeyFile      string
	SPIFFEBundleFile       string
	WebAuthnRPID           string
	WebAuthnRPDisplayName  string
	WebAuthnOrigins        []string
	GeoIPDB                string
	TrustedProxies         []string
	AlertWebhookToken      string
	OTELEndpoint           string
	OPAPolicy              string
	PKCS11TokenFile        string
	PKCS11Module           string
	PKCS11Helper           string
	PKCS11Label            string
	PKCS11URI              string
	FIPSRequired           bool
	SBOMFile               string
	PDFCertFile            string
	PDFKeyFile             string
	PDFTSAURL              string
	PDFLTV                 bool
	PDFLTVDir              string
	PDFLTVFetch            bool
	PDFLTA                 bool
	DrainTimeout           time.Duration
	RDPPublicHost          string // hostname in .rdp for native mstsc; empty/off = disabled
	RDPProxyBin            string // freerdp-proxy binary; empty = issue .rdp/token only
	RDPProxyCertFile       string
	RDPProxyKeyFile        string
	LicenseFile            string // path to license.json (T-52); empty → default max_assets=100
	SiteID                 string // SOW-GEO-HA site identity
	SiteRole               string // primary | standby | standalone
	SitePeerURL            string // optional peer /livez
	SiteReplicaDSN         string // optional PG DSN for lag probe
	SiteMaxLagSeconds      int    // 0 = don't fail readyz on lag
	GeoRecordingsSync      string // off | s3 | rsync (auto if unset)
	GeoRsyncTarget         string // rsync dest for primary→standby
	GeoRsyncSource         string // override source; default RecordingsDir
	GeoPublicURL           string // public URL for cutover drill (/geoz)
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:               env("KEEPPAM_HTTP_ADDR", ":8080"),
		DatabaseURL:            env("KEEPPAM_DATABASE_URL", "postgres://keeppam:keeppam@localhost:5432/keeppam?sslmode=disable"),
		RedisURL:               env("KEEPPAM_REDIS_URL", "redis://localhost:6379/0"),
		DataKeySource:          strings.ToLower(env("KEEPPAM_DATA_KEY_SOURCE", "env")),
		BootstrapAdminPassword: env("KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD", ""),
		SessionTTL:             durationEnv("KEEPPAM_SESSION_TTL", 8*time.Hour),
		ChallengeTTL:           durationEnv("KEEPPAM_CHALLENGE_TTL", 5*time.Minute),
		CookieSecure:           boolEnv("KEEPPAM_COOKIE_SECURE", false),
		CookieDomain:           env("KEEPPAM_COOKIE_DOMAIN", ""),
		CORSOrigin:             env("KEEPPAM_CORS_ORIGIN", "http://localhost:5173"),
		MaxFailedLogins:        intEnv("KEEPPAM_MAX_FAILED_LOGINS", 5),
		LockoutDuration:        durationEnv("KEEPPAM_LOCKOUT_DURATION", 15*time.Minute),
		RecordingsDir:          env("KEEPPAM_RECORDINGS_DIR", "./recordings"),
		RecordingsBackend:      strings.ToLower(env("KEEPPAM_RECORDINGS_BACKEND", "local")),
		S3Endpoint:             env("KEEPPAM_S3_ENDPOINT", ""),
		S3Bucket:               env("KEEPPAM_S3_BUCKET", ""),
		S3Region:               env("KEEPPAM_S3_REGION", "us-east-1"),
		S3Prefix:               env("KEEPPAM_S3_PREFIX", ""),
		S3ObjectLockMode:       strings.ToUpper(env("KEEPPAM_S3_OBJECT_LOCK_MODE", "")),
		S3ObjectLockDays:       intEnv("KEEPPAM_S3_OBJECT_LOCK_DAYS", 90),
		SSHAddr:                env("KEEPPAM_SSH_ADDR", ":2222"),
		SSHHostKeyPath:         env("KEEPPAM_SSH_HOST_KEY", "/tmp/keeppam-ssh-hostkey"),
		TelnetAddr:             env("KEEPPAM_TELNET_ADDR", ":2323"),
		TN3270Addr:             env("KEEPPAM_TN3270_ADDR", ":2324"),
		CitrixSocksAddr:        env("KEEPPAM_CITRIX_SOCKS_ADDR", ":1081"),
		CitrixPublicHost:       env("KEEPPAM_CITRIX_PUBLIC_HOST", ""),
		CitrixHDXPluginURL:     env("KEEPPAM_CITRIX_HDX_PLUGIN_URL", ""),
		CitrixHDXCallbackBase:  env("KEEPPAM_CITRIX_HDX_CALLBACK_BASE", env("KEEPPAM_PUBLIC_URL", "")),
		Mode:                   env("KEEPPAM_MODE", "all"),
		GuacdAddr:              env("KEEPPAM_GUACD_ADDR", "127.0.0.1:4822"),
		GuacencURL:             env("KEEPPAM_GUACENC_URL", ""),
		AccessRequestTTL:       durationEnv("KEEPPAM_ACCESS_REQUEST_TTL", 24*time.Hour),
		PostgresWireAddr:       env("KEEPPAM_PG_WIRE_ADDR", ":15432"),
		MySQLWireAddr:          env("KEEPPAM_MYSQL_WIRE_ADDR", ":13306"),
		MSSQLWireAddr:          env("KEEPPAM_MSSQL_WIRE_ADDR", ":11433"),
		K8sAPIAddr:             env("KEEPPAM_K8S_API_ADDR", ":16443"),
		K8sTLSCertFile:         env("KEEPPAM_K8S_TLS_CERT_FILE", ""),
		K8sTLSKeyFile:          env("KEEPPAM_K8S_TLS_KEY_FILE", ""),
		K8sTLSPath:             env("KEEPPAM_K8S_TLS_PATH", "/tmp/keeppam-k8s-tls.pem"),
		K8sPublicURL:           env("KEEPPAM_K8S_PUBLIC_URL", ""),
		TLSCertFile:            env("KEEPPAM_TLS_CERT_FILE", ""),
		TLSKeyFile:             env("KEEPPAM_TLS_KEY_FILE", ""),
		TLSClientCAFile:        env("KEEPPAM_TLS_CLIENT_CA_FILE", ""),
		TLSRequireClientCert:   boolEnv("KEEPPAM_TLS_REQUIRE_CLIENT_CERT", false),
		SPIFFETrustDomain:      strings.ToLower(strings.TrimSpace(env("KEEPPAM_SPIFFE_TRUST_DOMAIN", ""))),
		SPIFFESVIDFile:         env("KEEPPAM_SPIFFE_SVID_FILE", ""),
		SPIFFESVIDKeyFile:      env("KEEPPAM_SPIFFE_SVID_KEY_FILE", ""),
		SPIFFEBundleFile:       env("KEEPPAM_SPIFFE_BUNDLE_FILE", ""),
		WebAuthnRPDisplayName:  env("KEEPPAM_WEBAUTHN_RP_NAME", "KeepPAM"),
		GeoIPDB:                env("KEEPPAM_GEOIP_DB", ""),
		AlertWebhookToken:      strings.TrimSpace(env("KEEPPAM_ALERT_WEBHOOK_TOKEN", "")),
		OTELEndpoint:           strings.TrimSpace(env("KEEPPAM_OTEL_ENDPOINT", "")),
		OPAPolicy:              strings.TrimSpace(env("KEEPPAM_OPA_POLICY", "")),
		PKCS11TokenFile:        env("KEEPPAM_PKCS11_TOKEN_FILE", ""),
		PKCS11Module:           env("KEEPPAM_PKCS11_MODULE", ""),
		PKCS11Helper:           env("KEEPPAM_PKCS11_HELPER", ""),
		PKCS11Label:            firstNonEmpty(env("KEEPPAM_PKCS11_LABEL", ""), env("KEEPPAM_PKCS11_OBJECT", "")),
		PKCS11URI:              env("KEEPPAM_PKCS11_URI", ""),
		FIPSRequired:           boolEnv("KEEPPAM_FIPS_REQUIRED", false),
		SBOMFile:               env("KEEPPAM_SBOM_FILE", ""),
		PDFCertFile:            env("KEEPPAM_PDF_CERT_FILE", ""),
		PDFKeyFile:             env("KEEPPAM_PDF_KEY_FILE", ""),
		PDFTSAURL:              strings.TrimSpace(env("KEEPPAM_PDF_TSA_URL", "")),
		PDFLTV:                 boolEnv("KEEPPAM_PDF_LTV", false),
		PDFLTVDir:              strings.TrimSpace(env("KEEPPAM_PDF_LTV_DIR", "")),
		PDFLTVFetch:            boolEnv("KEEPPAM_PDF_LTV_FETCH", true),
		PDFLTA:                 boolEnv("KEEPPAM_PDF_LTA", false),
		DrainTimeout:           durationEnv("KEEPPAM_DRAIN_TIMEOUT", 90*time.Second),
		RDPPublicHost:          env("KEEPPAM_RDP_PUBLIC_HOST", ""),
		RDPProxyBin:            env("KEEPPAM_RDP_PROXY_BIN", ""),
		RDPProxyCertFile:       env("KEEPPAM_RDP_PROXY_CERT_FILE", ""),
		RDPProxyKeyFile:        env("KEEPPAM_RDP_PROXY_KEY_FILE", ""),
		LicenseFile:            env("KEEPPAM_LICENSE_FILE", ""),
		SiteID:                 env("KEEPPAM_SITE_ID", ""),
		SiteRole:               geoNormalizeRole(env("KEEPPAM_SITE_ROLE", "")),
		SitePeerURL:            env("KEEPPAM_SITE_PEER_URL", ""),
		SiteReplicaDSN:         env("KEEPPAM_SITE_REPLICA_DSN", ""),
		SiteMaxLagSeconds:      intEnv("KEEPPAM_SITE_MAX_LAG_SECONDS", 0),
		GeoRecordingsSync:      strings.ToLower(env("KEEPPAM_GEO_RECORDINGS_SYNC", "")),
		GeoRsyncTarget:         env("KEEPPAM_GEO_RSYNC_TARGET", ""),
		GeoRsyncSource:         env("KEEPPAM_GEO_RSYNC_SOURCE", ""),
		GeoPublicURL:           env("KEEPPAM_GEO_PUBLIC_URL", env("KEEPPAM_PUBLIC_URL", "")),
	}
	cfg.WebAuthnOrigins = splitCSV(env("KEEPPAM_WEBAUTHN_ORIGINS", cfg.CORSOrigin))
	cfg.WebAuthnRPID = env("KEEPPAM_WEBAUTHN_RP_ID", hostFromURL(cfg.CORSOrigin))
	cfg.TrustedProxies = splitCSV(env("KEEPPAM_TRUSTED_PROXIES", ""))
	switch cfg.Mode {
	case "all", "api", "ssh":
	default:
		return Config{}, fmt.Errorf("KEEPPAM_MODE must be all|api|ssh")
	}
	if cfg.Mode == "api" {
		cfg.SSHAddr = "off"
	}
	switch cfg.RecordingsBackend {
	case "local", "s3":
	default:
		return Config{}, fmt.Errorf("KEEPPAM_RECORDINGS_BACKEND must be local|s3")
	}
	switch cfg.DataKeySource {
	case "env", "file", "vault", "aws", "gcp", "azure", "pkcs11":
	default:
		return Config{}, fmt.Errorf("KEEPPAM_DATA_KEY_SOURCE must be env|file|vault|aws|gcp|azure|pkcs11")
	}
	switch strings.ToUpper(cfg.S3ObjectLockMode) {
	case "", "OFF", "NONE":
		cfg.S3ObjectLockMode = ""
	case "GOVERNANCE", "COMPLIANCE":
		cfg.S3ObjectLockMode = strings.ToUpper(cfg.S3ObjectLockMode)
	default:
		return Config{}, fmt.Errorf("KEEPPAM_S3_OBJECT_LOCK_MODE must be empty|GOVERNANCE|COMPLIANCE")
	}
	if cfg.S3ObjectLockMode != "" && (cfg.S3ObjectLockDays < 1 || cfg.S3ObjectLockDays > 36500) {
		return Config{}, fmt.Errorf("KEEPPAM_S3_OBJECT_LOCK_DAYS must be 1..36500")
	}
	if (cfg.SPIFFESVIDFile == "") != (cfg.SPIFFESVIDKeyFile == "") {
		return Config{}, fmt.Errorf("KEEPPAM_SPIFFE_SVID_FILE and KEEPPAM_SPIFFE_SVID_KEY_FILE must both be set")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("KEEPPAM_TLS_CERT_FILE and KEEPPAM_TLS_KEY_FILE must both be set")
	}
	if cfg.TLSCertFile == "" && cfg.SPIFFESVIDFile != "" {
		cfg.TLSCertFile = cfg.SPIFFESVIDFile
		cfg.TLSKeyFile = cfg.SPIFFESVIDKeyFile
	}
	if cfg.TLSRequireClientCert && cfg.TLSClientCAFile == "" && cfg.SPIFFEBundleFile == "" {
		return Config{}, fmt.Errorf("KEEPPAM_TLS_CLIENT_CA_FILE or KEEPPAM_SPIFFE_BUNDLE_FILE required when KEEPPAM_TLS_REQUIRE_CLIENT_CERT=true")
	}
	if (cfg.PDFCertFile == "") != (cfg.PDFKeyFile == "") {
		return Config{}, fmt.Errorf("KEEPPAM_PDF_CERT_FILE and KEEPPAM_PDF_KEY_FILE must both be set")
	}
	if cfg.PDFLTV && cfg.PDFTSAURL == "" {
		return Config{}, fmt.Errorf("KEEPPAM_PDF_LTV requires KEEPPAM_PDF_TSA_URL")
	}
	if cfg.PDFLTA && !cfg.PDFLTV {
		return Config{}, fmt.Errorf("KEEPPAM_PDF_LTA requires KEEPPAM_PDF_LTV")
	}
	return cfg, nil
}

func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func (c Config) clientCAReady() bool {
	return c.TLSClientCAFile != "" || c.SPIFFEBundleFile != ""
}

func (c Config) MTLSMode() string {
	if !c.TLSEnabled() || !c.clientCAReady() {
		return "off"
	}
	if c.TLSRequireClientCert {
		return "required"
	}
	return "optional"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolEnv(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func intEnv(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func durationEnv(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "localhost"
	}
	return u.Hostname()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func geoNormalizeRole(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "primary", "standby", "standalone":
		return s
	case "dr", "secondary":
		return "standby"
	case "":
		return "standalone"
	default:
		return "standalone"
	}
}
