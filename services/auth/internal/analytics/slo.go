package analytics

import (
	"context"
	"time"

	"github.com/keeppam/auth/internal/obs"
)

type SLOTargets struct {
	AuthP95Seconds          float64 `json:"auth_p95_seconds"`
	SessionSetupP95Seconds  float64 `json:"session_setup_p95_seconds"`
	AuditLagSeconds         float64 `json:"audit_lag_seconds"`
}

type SLO struct {
	GeneratedAt              time.Time  `json:"generated_at"`
	Targets                  SLOTargets `json:"targets"`
	AuthP95Seconds           *float64   `json:"auth_p95_seconds"`
	AuthSamples              int        `json:"auth_samples"`
	AuthBurn                 *float64   `json:"auth_burn,omitempty"`
	SessionSetupP95Seconds   *float64   `json:"session_setup_p95_seconds"`
	SessionSetupSamples      int        `json:"session_setup_samples"`
	SessionSetupBurn         *float64   `json:"session_setup_burn,omitempty"`
	ActiveSessions           int        `json:"active_sessions"`
	AuditExportLagSeconds    *int64     `json:"audit_export_lag_seconds"`
	AuditPending             int        `json:"audit_pending"`
	AuditLagBurn             *float64   `json:"audit_lag_burn,omitempty"`
	SIEMEnabled              bool       `json:"siem_enabled"`
	SIEMHealthy              bool       `json:"siem_healthy"`
	Breached                 bool       `json:"breached"`
}

func (s *Service) SLO(ctx context.Context) (SLO, error) {
	now := time.Now().UTC()
	out := SLO{
		GeneratedAt: now,
		Targets: SLOTargets{
			AuthP95Seconds:         obs.AuthP95Target.Seconds(),
			SessionSetupP95Seconds: obs.SessionSetupP95Target.Seconds(),
			AuditLagSeconds:        obs.AuditLagTarget.Seconds(),
		},
	}

	if p95, n := obs.Default.AuthP95(); n > 0 {
		v := p95
		b := obs.Burn(v, out.Targets.AuthP95Seconds)
		out.AuthP95Seconds = &v
		out.AuthSamples = n
		out.AuthBurn = &b
		if obs.Breached(&v, out.Targets.AuthP95Seconds, n) {
			out.Breached = true
		}
	}

	var setupP95 *float64
	var setupN int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (started_at - created_at))),
			COUNT(*)::int
		FROM sessions
		WHERE started_at IS NOT NULL
		  AND started_at >= created_at
		  AND started_at > NOW() - INTERVAL '24 hours'`).Scan(&setupP95, &setupN)
	if err != nil {
		return out, err
	}
	out.SessionSetupSamples = setupN
	if setupP95 != nil && setupN > 0 {
		v := *setupP95
		b := obs.Burn(v, out.Targets.SessionSetupP95Seconds)
		out.SessionSetupP95Seconds = &v
		out.SessionSetupBurn = &b
		if obs.Breached(&v, out.Targets.SessionSetupP95Seconds, setupN) {
			out.Breached = true
		}
	}

	_ = s.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE status='active'`).Scan(&out.ActiveSessions)

	siem, err := siemCorrelation(ctx, s.db.Pool, now)
	if err != nil {
		return out, err
	}
	out.SIEMEnabled = siem.Enabled && siem.Transport != "off"
	out.SIEMHealthy = siem.Healthy
	out.AuditPending = siem.PendingEvents
	out.AuditExportLagSeconds = siem.LagSeconds
	if out.SIEMEnabled && siem.LagSeconds != nil {
		lag := float64(*siem.LagSeconds)
		b := obs.Burn(lag, out.Targets.AuditLagSeconds)
		out.AuditLagBurn = &b
		if lag > out.Targets.AuditLagSeconds {
			out.Breached = true
		}
	}

	obs.Default.SetActiveSessions(int64(out.ActiveSessions))
	if siem.LagSeconds != nil {
		obs.Default.SetAuditLag(float64(*siem.LagSeconds), true)
	} else {
		obs.Default.SetAuditLag(0, false)
	}
	return out, nil
}
