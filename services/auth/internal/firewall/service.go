package firewall

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	PamGatewayCIDRs    []string   `json:"pam_gateway_cidrs"`
	ProbeURL           string       `json:"probe_url,omitempty"`
	ProbeQuorum        int          `json:"probe_quorum"`
	ProbeAgents        []ProbeAgent `json:"probe_agents"`
	ProbeIntervalHours int        `json:"probe_interval_hours"`
	AwxLaunchURL       string     `json:"awx_launch_url"`
	AwxToken           string     `json:"awx_token,omitempty"`
	HasAwxToken        bool       `json:"has_awx_token"`
	AwxAutoPush        bool       `json:"awx_auto_push"`
	LastProbeAt        *time.Time `json:"last_probe_at,omitempty"`
	LastPushAt         *time.Time `json:"last_push_at,omitempty"`
	LastPushError      string     `json:"last_push_error,omitempty"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
	env *crypto.Envelope
}

func New(db *store.DB, aud *audit.Service, env *crypto.Envelope) *Service {
	return &Service{db: db, aud: aud, env: env}
}

type loadedSettings struct {
	Settings
	awxTokenEnc []byte
}

func (s *Service) loadSettings(ctx context.Context) (Settings, []byte, error) {
	var out Settings
	var awxEnc []byte
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(pam_gateway_cidrs, '{}'), COALESCE(probe_url, ''), COALESCE(probe_quorum, 1),
			COALESCE(probe_interval_hours, 0),
			COALESCE(awx_launch_url, ''),
			awx_token_enc, COALESCE(awx_auto_push, FALSE), last_probe_at, last_push_at,
			COALESCE(last_push_error, ''), updated_at
		FROM firewall_settings WHERE id=1`).Scan(
		&out.PamGatewayCIDRs, &out.ProbeURL, &out.ProbeQuorum, &out.ProbeIntervalHours, &out.AwxLaunchURL, &awxEnc, &out.AwxAutoPush,
		&out.LastProbeAt, &out.LastPushAt, &out.LastPushError, &updatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Settings{PamGatewayCIDRs: []string{}}, nil, nil
		}
		return Settings{}, nil, err
	}
	if out.PamGatewayCIDRs == nil {
		out.PamGatewayCIDRs = []string{}
	}
	if out.ProbeQuorum < 1 {
		out.ProbeQuorum = 1
	}
	out.HasAwxToken = len(awxEnc) > 0
	out.UpdatedAt = &updatedAt
	agents, _ := s.ListProbeAgents(ctx)
	out.ProbeAgents = agents
	return out, awxEnc, nil
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	out, _, err := s.loadSettings(ctx)
	return out, err
}

func (s *Service) Put(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	cur, awxEnc, err := s.loadSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	cidrs, err := ValidateGatewayCIDRs(in.PamGatewayCIDRs)
	if err != nil {
		return Settings{}, err
	}
	probeURL := strings.TrimSpace(in.ProbeURL)
	if probeURL != "" {
		u, err := url.Parse(probeURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Settings{}, fmt.Errorf("invalid probe_url")
		}
	}
	awxURL := strings.TrimSpace(in.AwxLaunchURL)
	if awxURL != "" {
		u, err := url.Parse(awxURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Settings{}, fmt.Errorf("invalid awx_launch_url")
		}
	}
	interval := in.ProbeIntervalHours
	if interval < 0 || interval > 168 {
		return Settings{}, fmt.Errorf("probe_interval_hours: 0…168")
	}
	quorum := in.ProbeQuorum
	if quorum == 0 {
		quorum = cur.ProbeQuorum
	}
	if quorum < 1 || quorum > 16 {
		return Settings{}, fmt.Errorf("probe_quorum: 1…16")
	}
	if strings.TrimSpace(in.AwxToken) != "" {
		if s.env == nil {
			return Settings{}, fmt.Errorf("encryption unavailable")
		}
		awxEnc, err = s.env.Encrypt([]byte(strings.TrimSpace(in.AwxToken)))
		if err != nil {
			return Settings{}, err
		}
	}
	now := time.Now().UTC()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO firewall_settings (
			id, pam_gateway_cidrs, probe_url, probe_quorum, probe_interval_hours, awx_launch_url, awx_token_enc, awx_auto_push, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			pam_gateway_cidrs=$1, probe_url=$2, probe_quorum=$3, probe_interval_hours=$4, awx_launch_url=$5, awx_token_enc=$6,
			awx_auto_push=$7, updated_at=$8`,
		cidrs, probeURL, quorum, interval, awxURL, awxEnc, in.AwxAutoPush, now)
	if err != nil {
		return Settings{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "firewall.settings.updated", "settings", "firewall", ip, ua, map[string]any{
		"gateway_cidrs": cidrs, "probe_url": probeURL != "", "probe_quorum": quorum, "probe_interval_hours": interval,
		"awx_launch_url": awxURL != "", "awx_auto_push": in.AwxAutoPush, "prev_auto_push": cur.AwxAutoPush,
	})
	return s.Get(ctx)
}

func (s *Service) awxTokenPlain(enc []byte) ([]byte, error) {
	if len(enc) == 0 || s.env == nil {
		return nil, nil
	}
	return s.env.Decrypt(enc)
}

func (s *Service) Export(ctx context.Context, format string) (string, error) {
	cfg, err := s.Get(ctx)
	if err != nil {
		return "", err
	}
	targets, err := s.exportTargets(ctx)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "nft", "nftables":
		return GenerateNFT(targets, cfg.PamGatewayCIDRs), nil
	case "ansible", "yaml":
		return GenerateAnsible(targets, cfg.PamGatewayCIDRs), nil
	case "iptables", "":
		return GenerateIPTables(targets, cfg.PamGatewayCIDRs), nil
	default:
		return "", fmt.Errorf("unknown format %q (iptables|nft|ansible)", format)
	}
}

func (s *Service) exportTargets(ctx context.Context) ([]ExportTarget, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT name, address, port, protocol
		FROM assets
		WHERE status='active' AND COALESCE(pam_only, TRUE)=TRUE
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExportTarget
	for rows.Next() {
		var t ExportTarget
		if err := rows.Scan(&t.Name, &t.Address, &t.Port, &t.Protocol); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) ListTargets(ctx context.Context) ([]Target, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT name, address, hostname, port, protocol, pam_only
		FROM assets
		WHERE status='active' AND COALESCE(pam_only, TRUE)=TRUE
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.Name, &t.Address, &t.Hostname, &t.Port, &t.Protocol, &t.PamOnly); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) Probe(ctx context.Context, actorID uuid.UUID, ip, ua string) (ProbeReport, error) {
	cfg, _, err := s.loadSettings(ctx)
	if err != nil {
		return ProbeReport{}, err
	}
	quorum := cfg.ProbeQuorum
	if quorum < 1 {
		quorum = 1
	}

	agents, err := s.loadEnabledAgents(ctx)
	if err != nil {
		return ProbeReport{}, err
	}
	agentHealth := map[uuid.UUID]bool{}
	for _, a := range agents {
		ok, msg := checkAgentHealth(ctx, a.ProbeURL)
		s.touchAgentHealth(ctx, a.ID, ok, msg)
		agentHealth[a.ID] = ok
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, name, address, port, COALESCE(probe_segment, '')
		FROM assets
		WHERE status='active' AND COALESCE(pam_only, TRUE)=TRUE
		ORDER BY name`)
	if err != nil {
		return ProbeReport{}, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	report := ProbeReport{
		ProbedAt:         now,
		Results:          []ProbeResult{},
		ProbeQuorum:      quorum,
		ProbeAgentsTotal: len(agents),
	}
	via := "local"
	if len(agents) > 0 {
		via = "multi_probe"
	} else if strings.TrimSpace(cfg.ProbeURL) != "" {
		via = "probe_agent"
	}

	for rows.Next() {
		var t probeTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.Address, &t.Port, &t.ProbeSegment); err != nil {
			return ProbeReport{}, err
		}
		res := ProbeResult{
			AssetID: t.ID, Name: t.Name, Address: t.Address, Port: t.Port, Via: via, Quorum: quorum,
		}

		useAgents := agentsForAsset(agents, t.ProbeSegment)
		if len(useAgents) > 0 {
			res.Via = "multi_probe"
			var hits []bool
			for _, ag := range useAgents {
				hit := ProbeAgentHit{Agent: ag.Name, Segment: ag.Segment, Healthy: agentHealth[ag.ID]}
				tok, _ := s.agentTokenPlain(ag.tokenEnc)
				reachable, detail, perr := probeViaAgent(ctx, ag.ProbeURL, string(tok), t.Address, t.Port)
				if perr != nil {
					hit.Error = perr.Error()
				} else {
					hit.Reachable = reachable
					hit.Detail = detail
				}
				hits = append(hits, hit.Reachable)
				res.Agents = append(res.Agents, hit)
				if hit.Reachable {
					res.ReachableAgents++
				}
			}
			q := quorum
			if q > len(hits) {
				q = len(hits)
			}
			res.Quorum = q
			res.Reachable, _ = quorumReachable(hits, quorum)
			if res.Reachable {
				res.Detail = fmt.Sprintf("%d/%d agents reachable (quorum %d)", res.ReachableAgents, len(hits), q)
			}
		} else if strings.TrimSpace(cfg.ProbeURL) != "" {
			reachable, detail, perr := probeViaAgent(ctx, cfg.ProbeURL, "", t.Address, t.Port)
			if perr != nil {
				detail = perr.Error()
			}
			res.Reachable = reachable
			res.Detail = detail
			res.Via = "probe_agent"
		} else {
			reachable, detail := tcpReachable(ctx, t.Address, t.Port)
			res.Reachable = reachable
			res.Detail = detail
			res.Via = "local"
		}

		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE assets SET firewall_probe_at=$2, firewall_probe_reachable=$3, updated_at=$2
			WHERE id=$1`, t.ID, now, res.Reachable)
		if res.Reachable {
			report.ReachableCount++
		}
		report.Results = append(report.Results, res)
	}
	if err := rows.Err(); err != nil {
		return ProbeReport{}, err
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE firewall_settings SET last_probe_at=$1, updated_at=$1 WHERE id=1`, now)
	var actor *uuid.UUID
	if actorID != uuid.Nil {
		actor = &actorID
	}
	_ = s.aud.Record(ctx, actor, "firewall.probe.run", "settings", "firewall", ip, ua, map[string]any{
		"reachable": report.ReachableCount, "total": len(report.Results), "via": via,
		"probe_quorum": quorum, "probe_agents": len(agents), "scheduled": actor == nil,
	})
	return report, nil
}
