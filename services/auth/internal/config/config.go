package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr               string
	DatabaseURL            string
	RedisURL               string
	DataKey                []byte
	BootstrapAdminPassword string
	SessionTTL             time.Duration
	ChallengeTTL           time.Duration
	CookieSecure           bool
	CookieDomain           string
	CORSOrigin             string
	MaxFailedLogins        int
	LockoutDuration        time.Duration
	RecordingsDir          string
	SSHAddr                string
	SSHHostKeyPath         string
	Mode                   string // all | api | ssh
	GuacdAddr              string
	GuacencURL             string
	AccessRequestTTL       time.Duration
	PostgresWireAddr       string
	MySQLWireAddr          string
}

func Load() (Config, error) {
	keyB64 := env("KEEPPAM_DATA_KEY", "")
	if keyB64 == "" {
		return Config{}, fmt.Errorf("KEEPPAM_DATA_KEY is required (32-byte key, base64)")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return Config{}, fmt.Errorf("KEEPPAM_DATA_KEY must be base64-encoded 32 bytes")
	}

	cfg := Config{
		HTTPAddr:               env("KEEPPAM_HTTP_ADDR", ":8080"),
		DatabaseURL:            env("KEEPPAM_DATABASE_URL", "postgres://keeppam:keeppam@localhost:5432/keeppam?sslmode=disable"),
		RedisURL:               env("KEEPPAM_REDIS_URL", "redis://localhost:6379/0"),
		DataKey:                key,
		BootstrapAdminPassword: env("KEEPPAM_BOOTSTRAP_ADMIN_PASSWORD", ""),
		SessionTTL:             durationEnv("KEEPPAM_SESSION_TTL", 8*time.Hour),
		ChallengeTTL:           durationEnv("KEEPPAM_CHALLENGE_TTL", 5*time.Minute),
		CookieSecure:           boolEnv("KEEPPAM_COOKIE_SECURE", false),
		CookieDomain:           env("KEEPPAM_COOKIE_DOMAIN", ""),
		CORSOrigin:             env("KEEPPAM_CORS_ORIGIN", "http://localhost:5173"),
		MaxFailedLogins:        intEnv("KEEPPAM_MAX_FAILED_LOGINS", 5),
		LockoutDuration:        durationEnv("KEEPPAM_LOCKOUT_DURATION", 15*time.Minute),
		RecordingsDir:          env("KEEPPAM_RECORDINGS_DIR", "./recordings"),
		SSHAddr:                env("KEEPPAM_SSH_ADDR", ":2222"),
		SSHHostKeyPath:         env("KEEPPAM_SSH_HOST_KEY", "/tmp/keeppam-ssh-hostkey"),
		Mode:                   env("KEEPPAM_MODE", "all"),
		GuacdAddr:              env("KEEPPAM_GUACD_ADDR", "127.0.0.1:4822"),
		GuacencURL:             env("KEEPPAM_GUACENC_URL", ""),
		AccessRequestTTL:       durationEnv("KEEPPAM_ACCESS_REQUEST_TTL", 24*time.Hour),
		PostgresWireAddr:       env("KEEPPAM_PG_WIRE_ADDR", ":15432"),
		MySQLWireAddr:          env("KEEPPAM_MYSQL_WIRE_ADDR", ":13306"),
	}
	switch cfg.Mode {
	case "all", "api", "ssh":
	default:
		return Config{}, fmt.Errorf("KEEPPAM_MODE must be all|api|ssh")
	}
	if cfg.Mode == "api" {
		cfg.SSHAddr = "off"
	}
	return cfg, nil
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
