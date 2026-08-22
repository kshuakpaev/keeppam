package geo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Role of this KeepPAM site in a multi-site deployment (SOW-GEO-HA).
const (
	RolePrimary   = "primary"
	RoleStandby   = "standby"
	RoleStandalone = "standalone"
)

type Config struct {
	SiteID        string
	Role          string // primary | standby | standalone
	PeerURL       string // optional peer site health URL
	ReplicaDSN    string // optional DSN to measure lag (standby PG or remote replica)
	MaxLagSeconds int    // 0 = don't fail ready on lag
}

func NormalizeRole(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case RolePrimary, RoleStandby, RoleStandalone:
		return s
	case "dr", "secondary":
		return RoleStandby
	case "":
		return RoleStandalone
	default:
		return RoleStandalone
	}
}

func (c Config) Enabled() bool {
	return strings.TrimSpace(c.SiteID) != "" || c.Role == RolePrimary || c.Role == RoleStandby
}

func (c Config) IsStandby() bool {
	return NormalizeRole(c.Role) == RoleStandby
}

func (c Config) AllowsSessionWrites() bool {
	return !c.IsStandby()
}

type Status struct {
	SiteID          string  `json:"site_id"`
	Role            string  `json:"role"`
	PeerURL         string  `json:"peer_url,omitempty"`
	AllowsWrites    bool    `json:"allows_writes"`
	InRecovery      *bool   `json:"pg_in_recovery,omitempty"`
	LagSeconds      *float64 `json:"lag_seconds,omitempty"`
	LagOK           *bool   `json:"lag_ok,omitempty"`
	MaxLagSeconds   int     `json:"max_lag_seconds,omitempty"`
	ReplicaProbe    string  `json:"replica_probe,omitempty"` // ok | error | skipped
	ReplicaError    string  `json:"replica_error,omitempty"`
	PeerOK          *bool   `json:"peer_ok,omitempty"`
	PeerError       string  `json:"peer_error,omitempty"`
	Hint            string  `json:"hint,omitempty"`
	GeneratedAt     time.Time `json:"generated_at"`
}

// Probe builds status using optional replica DSN (standby PG).
func Probe(ctx context.Context, cfg Config) Status {
	cfg.Role = NormalizeRole(cfg.Role)
	st := Status{
		SiteID:        cfg.SiteID,
		Role:          cfg.Role,
		PeerURL:       strings.TrimSpace(cfg.PeerURL),
		AllowsWrites:  cfg.AllowsSessionWrites(),
		MaxLagSeconds: cfg.MaxLagSeconds,
		ReplicaProbe:  "skipped",
		GeneratedAt:   time.Now().UTC(),
		Hint:          "docs/geo-ha.txt",
	}
	dsn := strings.TrimSpace(cfg.ReplicaDSN)
	if dsn == "" {
		if cfg.IsStandby() {
			st.Hint = "standby without KEEPPAM_SITE_REPLICA_DSN — set DSN to local PG for lag"
		}
		return st
	}
	lag, recovery, err := measureLag(ctx, dsn)
	if err != nil {
		st.ReplicaProbe = "error"
		st.ReplicaError = err.Error()
		return st
	}
	st.ReplicaProbe = "ok"
	st.InRecovery = &recovery
	st.LagSeconds = &lag
	ok := true
	if cfg.MaxLagSeconds > 0 && lag > float64(cfg.MaxLagSeconds) {
		ok = false
	}
	st.LagOK = &ok
	return st
}

func measureLag(ctx context.Context, dsn string) (lagSec float64, inRecovery bool, err error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return 0, false, err
	}
	defer pool.Close()
	if err := pool.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		return 0, false, err
	}
	if !inRecovery {
		// Connected to a primary — lag N/A; treat as 0 for probe success.
		return 0, false, nil
	}
	var sec *float64
	err = pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))`).Scan(&sec)
	if err != nil {
		return 0, true, err
	}
	if sec == nil {
		return 0, true, fmt.Errorf("replay timestamp unavailable")
	}
	if *sec < 0 {
		return 0, true, nil
	}
	return *sec, true, nil
}

// FenceError is returned when standby must not accept session traffic.
func FenceError(cfg Config) error {
	if cfg.AllowsSessionWrites() {
		return nil
	}
	id := cfg.SiteID
	if id == "" {
		id = "standby"
	}
	return fmt.Errorf("site %s is standby — session writes fenced (promote first; docs/geo-ha.txt)", id)
}
