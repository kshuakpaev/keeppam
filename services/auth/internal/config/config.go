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
	Mode                   string // all | api | ssh
	GuacdAddr              string
	GuacencURL             string
	AccessRequestTTL       time.Duration
	PostgresWireAddr       string
	MySQLWireAddr          string
	K8sAPIAddr             string
	K8sTLSCertFile         string
	K8sTLSKeyFile          string
	K8sTLSPath             string
	K8sPublicURL           string
	TLSCertFile            string
	TLSKeyFile             string
	TLSClientCAFile        string
	TLSRequireClientCert   bool
	WebAuthnRPID           string
	WebAuthnRPDisplayName  string
	WebAuthnOrigins        []string
	GeoIPDB                string
	AlertWebhookToken      string
	OTELEndpoint           string
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
		Mode:                   env("KEEPPAM_MODE", "all"),
		GuacdAddr:              env("KEEPPAM_GUACD_ADDR", "127.0.0.1:4822"),
		GuacencURL:             env("KEEPPAM_GUACENC_URL", ""),
		AccessRequestTTL:       durationEnv("KEEPPAM_ACCESS_REQUEST_TTL", 24*time.Hour),
		PostgresWireAddr:       env("KEEPPAM_PG_WIRE_ADDR", ":15432"),
		MySQLWireAddr:          env("KEEPPAM_MYSQL_WIRE_ADDR", ":13306"),
		K8sAPIAddr:             env("KEEPPAM_K8S_API_ADDR", ":16443"),
		K8sTLSCertFile:         env("KEEPPAM_K8S_TLS_CERT_FILE", ""),
		K8sTLSKeyFile:          env("KEEPPAM_K8S_TLS_KEY_FILE", ""),
		K8sTLSPath:             env("KEEPPAM_K8S_TLS_PATH", "/tmp/keeppam-k8s-tls.pem"),
		K8sPublicURL:           env("KEEPPAM_K8S_PUBLIC_URL", ""),
		TLSCertFile:            env("KEEPPAM_TLS_CERT_FILE", ""),
		TLSKeyFile:             env("KEEPPAM_TLS_KEY_FILE", ""),
		TLSClientCAFile:        env("KEEPPAM_TLS_CLIENT_CA_FILE", ""),
		TLSRequireClientCert:   boolEnv("KEEPPAM_TLS_REQUIRE_CLIENT_CERT", false),
		WebAuthnRPDisplayName:  env("KEEPPAM_WEBAUTHN_RP_NAME", "KeepPAM"),
		GeoIPDB:                env("KEEPPAM_GEOIP_DB", ""),
		AlertWebhookToken:      strings.TrimSpace(env("KEEPPAM_ALERT_WEBHOOK_TOKEN", "")),
		OTELEndpoint:           strings.TrimSpace(env("KEEPPAM_OTEL_ENDPOINT", "")),
	}
	cfg.WebAuthnOrigins = splitCSV(env("KEEPPAM_WEBAUTHN_ORIGINS", cfg.CORSOrigin))
	cfg.WebAuthnRPID = env("KEEPPAM_WEBAUTHN_RP_ID", hostFromURL(cfg.CORSOrigin))
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
	case "env", "file", "vault", "aws", "gcp", "azure":
	default:
		return Config{}, fmt.Errorf("KEEPPAM_DATA_KEY_SOURCE must be env|file|vault|aws|gcp|azure")
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
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("KEEPPAM_TLS_CERT_FILE and KEEPPAM_TLS_KEY_FILE must both be set")
	}
	if cfg.TLSRequireClientCert && cfg.TLSClientCAFile == "" {
		return Config{}, fmt.Errorf("KEEPPAM_TLS_CLIENT_CA_FILE required when KEEPPAM_TLS_REQUIRE_CLIENT_CERT=true")
	}
	return cfg, nil
}

func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func (c Config) MTLSMode() string {
	if !c.TLSEnabled() || c.TLSClientCAFile == "" {
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
