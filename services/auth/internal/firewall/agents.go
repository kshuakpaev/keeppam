package firewall

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

const maxProbeAgents = 16

var reProbeAgentName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type ProbeAgent struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	Segment      string     `json:"segment"`
	ProbeURL     string     `json:"probe_url"`
	HasToken     bool       `json:"has_token"`
	Token        string     `json:"token,omitempty"`
	Enabled      bool       `json:"enabled"`
	LastHealthAt *time.Time `json:"last_health_at,omitempty"`
	LastHealthOK *bool      `json:"last_health_ok,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
}

type ProbeAgentInput struct {
	Name     string `json:"name"`
	Segment  string `json:"segment"`
	ProbeURL string `json:"probe_url"`
	Token    string `json:"token,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type loadedProbeAgent struct {
	ProbeAgent
	tokenEnc []byte
}

func normalizeSegment(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeProbeAgentInput(in ProbeAgentInput) (ProbeAgentInput, error) {
	name := strings.TrimSpace(in.Name)
	if !reProbeAgentName.MatchString(name) {
		return ProbeAgentInput{}, fmt.Errorf("probe agent name must match [a-z][a-z0-9_-]{0,31}")
	}
	probeURL := strings.TrimSpace(in.ProbeURL)
	if probeURL == "" {
		return ProbeAgentInput{}, fmt.Errorf("probe_url required")
	}
	u, err := url.Parse(probeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ProbeAgentInput{}, fmt.Errorf("invalid probe_url")
	}
	if !strings.HasSuffix(strings.TrimRight(probeURL, "/"), "/probe") {
		return ProbeAgentInput{}, fmt.Errorf("probe_url must end with /probe")
	}
	return ProbeAgentInput{
		Name: name, Segment: normalizeSegment(in.Segment), ProbeURL: probeURL, Token: strings.TrimSpace(in.Token), Enabled: in.Enabled,
	}, nil
}

func (s *Service) ListProbeAgents(ctx context.Context) ([]ProbeAgent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, COALESCE(segment,''), probe_url, token_enc, enabled,
			last_health_at, last_health_ok, COALESCE(last_error,'')
		FROM firewall_probe_agents
		ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeAgent
	for rows.Next() {
		var a ProbeAgent
		var enc []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Segment, &a.ProbeURL, &enc, &a.Enabled,
			&a.LastHealthAt, &a.LastHealthOK, &a.LastError); err != nil {
			return nil, err
		}
		a.HasToken = len(enc) > 0
		out = append(out, a)
	}
	if out == nil {
		out = []ProbeAgent{}
	}
	return out, rows.Err()
}

func (s *Service) ReplaceProbeAgents(ctx context.Context, actorID uuid.UUID, quorum int, raw []ProbeAgentInput, ip, ua string) ([]ProbeAgent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if quorum < 1 || quorum > 16 {
		return nil, fmt.Errorf("probe_quorum: 1…16")
	}
	if len(raw) > maxProbeAgents {
		return nil, fmt.Errorf("at most %d probe agents", maxProbeAgents)
	}
	seen := map[string]struct{}{}
	norm := make([]ProbeAgentInput, 0, len(raw))
	for i, in := range raw {
		n, err := normalizeProbeAgentInput(in)
		if err != nil {
			return nil, fmt.Errorf("probe_agents[%d]: %w", i, err)
		}
		if _, ok := seen[n.Name]; ok {
			return nil, fmt.Errorf("duplicate probe agent %q", n.Name)
		}
		seen[n.Name] = struct{}{}
		norm = append(norm, n)
	}
	if quorum > len(norm) && len(norm) > 0 {
		return nil, fmt.Errorf("probe_quorum cannot exceed agent count")
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	prevEnc := map[string][]byte{}
	prevRows, err := tx.Query(ctx, `SELECT name, token_enc FROM firewall_probe_agents`)
	if err != nil {
		return nil, err
	}
	for prevRows.Next() {
		var name string
		var enc []byte
		if err := prevRows.Scan(&name, &enc); err != nil {
			prevRows.Close()
			return nil, err
		}
		prevEnc[name] = enc
	}
	prevRows.Close()

	if _, err := tx.Exec(ctx, `DELETE FROM firewall_probe_agents`); err != nil {
		return nil, err
	}
	for i, n := range norm {
		var enc []byte
		if n.Token != "" {
			if s.env == nil {
				return nil, fmt.Errorf("encryption unavailable")
			}
			enc, err = s.env.Encrypt([]byte(n.Token))
			if err != nil {
				return nil, err
			}
		} else if old, ok := prevEnc[n.Name]; ok {
			enc = old
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO firewall_probe_agents (id, name, segment, probe_url, token_enc, enabled, sort_order, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
			store.NewID(), n.Name, n.Segment, n.ProbeURL, enc, n.Enabled, i); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE firewall_settings SET probe_quorum=$1, updated_at=NOW() WHERE id=1`, quorum); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_ = s.aud.Record(ctx, &actorID, "firewall.probe_agents.updated", "settings", "firewall", ip, ua, map[string]any{
		"count": len(norm), "probe_quorum": quorum,
	})
	return s.ListProbeAgents(ctx)
}

func (s *Service) loadEnabledAgents(ctx context.Context) ([]loadedProbeAgent, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, COALESCE(segment,''), probe_url, token_enc, enabled,
			last_health_at, last_health_ok, COALESCE(last_error,'')
		FROM firewall_probe_agents
		WHERE enabled=TRUE
		ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []loadedProbeAgent
	for rows.Next() {
		var a loadedProbeAgent
		if err := rows.Scan(&a.ID, &a.Name, &a.Segment, &a.ProbeURL, &a.tokenEnc, &a.Enabled,
			&a.LastHealthAt, &a.LastHealthOK, &a.LastError); err != nil {
			return nil, err
		}
		a.HasToken = len(a.tokenEnc) > 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func agentsForAsset(agents []loadedProbeAgent, assetSegment string) []loadedProbeAgent {
	assetSegment = normalizeSegment(assetSegment)
	if len(agents) == 0 {
		return nil
	}
	if assetSegment == "" {
		return agents
	}
	var out []loadedProbeAgent
	for _, a := range agents {
		if a.Segment == "" || a.Segment == assetSegment {
			out = append(out, a)
		}
	}
	return out
}

func quorumReachable(hits []bool, quorum int) (reachable bool, usedQuorum int) {
	if len(hits) == 0 {
		return false, 0
	}
	usedQuorum = quorum
	if usedQuorum < 1 {
		usedQuorum = 1
	}
	if usedQuorum > len(hits) {
		usedQuorum = len(hits)
	}
	n := 0
	for _, h := range hits {
		if h {
			n++
		}
	}
	return n >= usedQuorum, usedQuorum
}

func agentHealthURL(probeURL string) string {
	u, err := url.Parse(strings.TrimSpace(probeURL))
	if err != nil {
		return ""
	}
	u.Path = "/healthz"
	u.RawQuery = ""
	return u.String()
}

func checkAgentHealth(ctx context.Context, probeURL string) (bool, string) {
	healthURL := agentHealthURL(probeURL)
	if healthURL == "" {
		return false, "invalid probe_url"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, fmt.Sprintf("health HTTP %d", resp.StatusCode)
	}
	return true, ""
}

func (s *Service) touchAgentHealth(ctx context.Context, id uuid.UUID, ok bool, errMsg string) {
	now := time.Now().UTC()
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE firewall_probe_agents SET last_health_at=$2, last_health_ok=$3, last_error=$4, updated_at=$2
		WHERE id=$1`, id, now, ok, errMsg)
}

func (s *Service) agentTokenPlain(enc []byte) ([]byte, error) {
	if len(enc) == 0 || s.env == nil {
		return nil, nil
	}
	return s.env.Decrypt(enc)
}

func (s *Service) probeQuorum(ctx context.Context) (int, error) {
	var q int
	err := s.db.Pool.QueryRow(ctx, `SELECT COALESCE(probe_quorum, 1) FROM firewall_settings WHERE id=1`).Scan(&q)
	if err == pgx.ErrNoRows {
		return 1, nil
	}
	if q < 1 {
		q = 1
	}
	return q, err
}
