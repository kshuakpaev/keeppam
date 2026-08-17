package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const probeTimeout = 4 * time.Second

type ProbeAgentHit struct {
	Agent     string `json:"agent"`
	Segment   string `json:"segment,omitempty"`
	Reachable bool   `json:"reachable"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
	Healthy   bool   `json:"healthy"`
}

type ProbeResult struct {
	AssetID         string          `json:"asset_id"`
	Name            string          `json:"name"`
	Address         string          `json:"address"`
	Port            int             `json:"port"`
	Reachable       bool            `json:"reachable"`
	Detail          string          `json:"detail,omitempty"`
	Via             string          `json:"via"` // local|probe_agent|multi_probe
	Agents          []ProbeAgentHit `json:"agents,omitempty"`
	ReachableAgents int             `json:"reachable_agents,omitempty"`
	Quorum          int             `json:"quorum,omitempty"`
}

type ProbeReport struct {
	ProbedAt         time.Time     `json:"probed_at"`
	ReachableCount   int           `json:"reachable_count"`
	ProbeQuorum      int           `json:"probe_quorum"`
	ProbeAgentsTotal int           `json:"probe_agents_total"`
	Results          []ProbeResult `json:"results"`
}

type probeTarget struct {
	ID            string
	Name          string
	Address       string
	Port          int
	ProbeSegment  string
}

func tcpReachable(ctx context.Context, host string, port int) (bool, string) {
	if net.ParseIP(host) == nil {
		return false, "non-ip address"
	}
	d := net.Dialer{Timeout: probeTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}

func probeViaAgent(ctx context.Context, probeURL, token, host string, port int) (bool, string, error) {
	body, _ := json.Marshal(map[string]any{"host": host, "port": port})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("probe agent HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		Reachable bool   `json:"reachable"`
		Detail    string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, "", fmt.Errorf("probe agent response: %w", err)
	}
	return out.Reachable, out.Detail, nil
}
