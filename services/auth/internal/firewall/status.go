package firewall

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"
)

type AssetStatus struct {
	ID                     uuid.UUID  `json:"id"`
	Name                   string     `json:"name"`
	Address                string     `json:"address"`
	Port                   int        `json:"port"`
	Protocol               string     `json:"protocol"`
	PamOnly                bool       `json:"pam_only"`
	FirewallAppliedAt      *time.Time `json:"firewall_applied_at,omitempty"`
	FirewallProbeAt        *time.Time `json:"firewall_probe_at,omitempty"`
	FirewallProbeReachable *bool      `json:"firewall_probe_reachable,omitempty"`
	Gaps                   []string   `json:"gaps,omitempty"`
}

type StatusReport struct {
	PamOnlyCount           int           `json:"pam_only_count"`
	GatewayCIDRsConfigured bool          `json:"gateway_cidrs_configured"`
	GatewayCIDRs           []string      `json:"gateway_cidrs"`
	UnappliedCount         int           `json:"unapplied_count"`
	NonIPCount             int           `json:"non_ip_count"`
	ProbeReachableCount    int           `json:"probe_reachable_count"`
	ProbeQuorum            int           `json:"probe_quorum"`
	ProbeAgentsTotal       int           `json:"probe_agents_total"`
	ProbeAgentsHealthy     int           `json:"probe_agents_healthy"`
	LastProbeAt            *time.Time    `json:"last_probe_at,omitempty"`
	LastPushAt             *time.Time    `json:"last_push_at,omitempty"`
	LastPushError          string        `json:"last_push_error,omitempty"`
	Ready                  bool          `json:"ready"`
	Assets                 []AssetStatus `json:"assets"`
}

func (s *Service) Status(ctx context.Context) (StatusReport, error) {
	cfg, _, err := s.loadSettings(ctx)
	if err != nil {
		return StatusReport{}, err
	}
	gatewayOK := len(cfg.PamGatewayCIDRs) > 0

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, address, port, protocol, COALESCE(pam_only, TRUE), firewall_applied_at,
			firewall_probe_at, firewall_probe_reachable
		FROM assets
		WHERE status='active' AND COALESCE(pam_only, TRUE)=TRUE
		ORDER BY name`)
	if err != nil {
		return StatusReport{}, err
	}
	defer rows.Close()

	out := StatusReport{
		GatewayCIDRsConfigured: gatewayOK,
		GatewayCIDRs:           cfg.PamGatewayCIDRs,
		LastProbeAt:            cfg.LastProbeAt,
		LastPushAt:             cfg.LastPushAt,
		LastPushError:          cfg.LastPushError,
		ProbeQuorum:            cfg.ProbeQuorum,
		ProbeAgentsTotal:       len(cfg.ProbeAgents),
		Assets:                 []AssetStatus{},
	}
	if out.ProbeQuorum < 1 {
		out.ProbeQuorum = 1
	}
	for _, ag := range cfg.ProbeAgents {
		if ag.Enabled && ag.LastHealthOK != nil && *ag.LastHealthOK {
			out.ProbeAgentsHealthy++
		}
	}
	if out.GatewayCIDRs == nil {
		out.GatewayCIDRs = []string{}
	}

	for rows.Next() {
		var a AssetStatus
		if err := rows.Scan(&a.ID, &a.Name, &a.Address, &a.Port, &a.Protocol, &a.PamOnly,
			&a.FirewallAppliedAt, &a.FirewallProbeAt, &a.FirewallProbeReachable); err != nil {
			return StatusReport{}, err
		}
		a.Gaps = assetGaps(a, gatewayOK)
		out.Assets = append(out.Assets, a)
		out.PamOnlyCount++
		if a.FirewallAppliedAt == nil {
			out.UnappliedCount++
		}
		if net.ParseIP(a.Address) == nil {
			out.NonIPCount++
		}
		if a.FirewallProbeReachable != nil && *a.FirewallProbeReachable {
			out.ProbeReachableCount++
		}
	}
	if err := rows.Err(); err != nil {
		return StatusReport{}, err
	}
	out.Ready = gatewayOK && out.PamOnlyCount > 0 && out.UnappliedCount == 0 && out.NonIPCount == 0 && out.ProbeReachableCount == 0
	if out.PamOnlyCount == 0 {
		out.Ready = gatewayOK
	}
	return out, nil
}

func assetGaps(a AssetStatus, gatewayOK bool) []string {
	var gaps []string
	if !gatewayOK {
		gaps = append(gaps, "no_gateway_cidrs")
	}
	if a.FirewallAppliedAt == nil {
		gaps = append(gaps, "rules_not_applied")
	}
	if net.ParseIP(a.Address) == nil {
		gaps = append(gaps, "non_ip_address")
	}
	if a.FirewallProbeReachable != nil && *a.FirewallProbeReachable {
		gaps = append(gaps, "probe_reachable")
	}
	return gaps
}

func (s *Service) MarkApplied(ctx context.Context, actorID, assetID uuid.UUID, ip, ua string) error {
	now := time.Now().UTC()
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE assets SET firewall_applied_at=$2, updated_at=$2
		WHERE id=$1 AND status='active' AND COALESCE(pam_only, TRUE)=TRUE`, assetID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotPamOnly
	}
	_ = s.aud.Record(ctx, &actorID, "asset.firewall.applied", "asset", assetID.String(), ip, ua, map[string]any{
		"applied_at": now,
	})
	s.maybeAutoPush(ctx, actorID, ip, ua)
	return nil
}
