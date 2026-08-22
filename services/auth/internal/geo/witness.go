package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const witnessRedisKey = "geo:witness:primary"

// WitnessConfig for split-brain fencing (SOW-GEO-HA phase 4).
type WitnessConfig struct {
	Mode         string // off | peer | redis | http | auto
	RedisURL     string // shared witness Redis (redis mode)
	HTTPURL      string // external witness service (http mode)
	LeaseSeconds int    // lease TTL
}

func (w WitnessConfig) EffectiveMode(cfg Config) string {
	m := strings.ToLower(strings.TrimSpace(w.Mode))
	switch m {
	case "off":
		return "off"
	case "peer", "redis", "http":
		return m
	default:
		if w.HTTPURL != "" {
			return "http"
		}
		if w.RedisURL != "" {
			return "redis"
		}
		if strings.TrimSpace(cfg.PeerURL) != "" {
			return "peer"
		}
		return "off"
	}
}

func (w WitnessConfig) leaseTTL() time.Duration {
	if w.LeaseSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(w.LeaseSeconds) * time.Second
}

type PeerInfo struct {
	SiteID       string `json:"site_id"`
	Role         string `json:"role"`
	AllowsWrites bool   `json:"allows_writes"`
}

type WitnessStatus struct {
	Mode             string     `json:"mode"`
	HolderSiteID     string     `json:"holder_site_id,omitempty"`
	LocalHolder      bool       `json:"local_holder"`
	SplitBrain       bool       `json:"split_brain"`
	SplitBrainDetail string     `json:"split_brain_detail,omitempty"`
	Peer             *PeerInfo  `json:"peer,omitempty"`
	PeerReachable    bool       `json:"peer_reachable"`
	LeaseExpiresIn   *float64   `json:"lease_expires_in_sec,omitempty"`
	OK               bool       `json:"ok"`
	Hint             string     `json:"hint"`
	GeneratedAt      time.Time  `json:"generated_at"`
}

// ProbePeerInfo GETs peer /geoz.
func ProbePeerInfo(ctx context.Context, peerURL string) (PeerInfo, error) {
	peerURL = strings.TrimSpace(peerURL)
	if peerURL == "" {
		return PeerInfo{}, fmt.Errorf("peer url empty")
	}
	if !strings.Contains(peerURL, "://") {
		peerURL = "http://" + peerURL
	}
	u := strings.TrimRight(peerURL, "/")
	if !strings.HasSuffix(u, "/geoz") {
		u += "/geoz"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PeerInfo{}, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return PeerInfo{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 256))
		return PeerInfo{}, fmt.Errorf("peer HTTP %d: %s", res.StatusCode, string(b))
	}
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&body); err != nil {
		return PeerInfo{}, err
	}
	pi := PeerInfo{
		SiteID: strVal(body["site_id"]),
		Role:   NormalizeRole(strVal(body["role"])),
	}
	if aw, ok := body["allows_writes"].(bool); ok {
		pi.AllowsWrites = aw
	}
	return pi, nil
}

func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// EvaluateWitness checks peer / redis / http witness and detects split-brain.
func EvaluateWitness(ctx context.Context, cfg Config, wc WitnessConfig, appRedis *redis.Client) WitnessStatus {
	cfg.Role = NormalizeRole(cfg.Role)
	mode := wc.EffectiveMode(cfg)
	st := WitnessStatus{
		Mode: mode, OK: true, Hint: "docs/geo-ha-witness.txt",
		GeneratedAt: time.Now().UTC(),
	}
	if mode == "off" {
		st.Hint = "witness off — set KEEPPAM_GEO_WITNESS_MODE or peer URL"
		return st
	}

	// Peer check (always when peer URL set, also supplementary for redis/http)
	if peer := strings.TrimSpace(cfg.PeerURL); peer != "" {
		pi, err := ProbePeerInfo(ctx, peer)
		if err != nil {
			st.PeerReachable = false
			if mode == "peer" {
				st.OK = false
				st.SplitBrainDetail = "peer unreachable: " + err.Error()
			}
		} else {
			st.PeerReachable = true
			st.Peer = &pi
			if cfg.Role == RolePrimary && (pi.AllowsWrites || NormalizeRole(pi.Role) == RolePrimary) {
				if pi.SiteID != cfg.SiteID {
					st.SplitBrain = true
					st.SplitBrainDetail = fmt.Sprintf("peer %s role=%s allows_writes=%v", pi.SiteID, pi.Role, pi.AllowsWrites)
					st.OK = false
				}
			}
		}
	}

	switch mode {
	case "redis":
		holder, ttl, err := renewRedisLease(ctx, wc, cfg.SiteID, appRedis)
		st.HolderSiteID = holder
		st.LocalHolder = holder == cfg.SiteID && cfg.SiteID != ""
		if ttl > 0 {
			sec := ttl.Seconds()
			st.LeaseExpiresIn = &sec
		}
		if err != nil {
			st.OK = false
			st.SplitBrainDetail = err.Error()
		} else if cfg.Role == RolePrimary && !st.LocalHolder && holder != "" {
			st.SplitBrain = true
			st.SplitBrainDetail = fmt.Sprintf("redis witness held by %s", holder)
			st.OK = false
		}
	case "http":
		holder, err := httpWitnessAcquire(ctx, wc, cfg.SiteID)
		st.HolderSiteID = holder
		st.LocalHolder = holder == cfg.SiteID && cfg.SiteID != ""
		if err != nil {
			st.OK = false
			st.SplitBrainDetail = err.Error()
		} else if cfg.Role == RolePrimary && !st.LocalHolder && holder != "" {
			st.SplitBrain = true
			st.SplitBrainDetail = fmt.Sprintf("http witness held by %s", holder)
			st.OK = false
		}
	}

	if st.SplitBrain {
		st.OK = false
	}
	return st
}

func renewRedisLease(ctx context.Context, wc WitnessConfig, siteID string, appRedis *redis.Client) (holder string, ttl time.Duration, err error) {
	rdb, closeFn, err := witnessRedisClient(wc, appRedis)
	if err != nil {
		return "", 0, err
	}
	if closeFn != nil {
		defer closeFn()
	}
	siteID = strings.TrimSpace(siteID)
	if siteID == "" {
		return "", 0, fmt.Errorf("site_id required for redis witness")
	}
	ttl = wc.leaseTTL()
	cur, err := rdb.Get(ctx, witnessRedisKey).Result()
	if err == redis.Nil {
		ok, err := rdb.SetNX(ctx, witnessRedisKey, siteID, ttl).Result()
		if err != nil {
			return "", 0, err
		}
		if ok {
			return siteID, ttl, nil
		}
		cur, _ = rdb.Get(ctx, witnessRedisKey).Result()
	}
	if cur == siteID {
		_ = rdb.Expire(ctx, witnessRedisKey, ttl).Err()
		rem, _ := rdb.TTL(ctx, witnessRedisKey).Result()
		return siteID, rem, nil
	}
	return cur, 0, nil
}

func witnessRedisClient(wc WitnessConfig, appRedis *redis.Client) (*redis.Client, func(), error) {
	url := strings.TrimSpace(wc.RedisURL)
	if url == "" {
		if appRedis == nil {
			return nil, nil, fmt.Errorf("witness redis not configured")
		}
		return appRedis, nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, nil, err
	}
	c := redis.NewClient(opts)
	return c, func() { _ = c.Close() }, nil
}

func httpWitnessAcquire(ctx context.Context, wc WitnessConfig, siteID string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(wc.HTTPURL), "/")
	if base == "" {
		return "", fmt.Errorf("witness http url empty")
	}
	body, _ := json.Marshal(map[string]any{
		"site_id": siteID, "ttl_seconds": int(wc.leaseTTL().Seconds()),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/lease", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode == http.StatusConflict {
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return strVal(out["holder_site_id"]), nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("witness HTTP %d: %s", res.StatusCode, string(b))
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	return strVal(out["holder_site_id"]), nil
}

// WriteFenceError blocks session writes for standby or split-brain primary.
func WriteFenceError(ctx context.Context, cfg Config, wc WitnessConfig, rdb *redis.Client) error {
	if err := FenceError(cfg); err != nil {
		return err
	}
	if NormalizeRole(cfg.Role) != RolePrimary {
		return nil
	}
	ws := EvaluateWitness(ctx, cfg, wc, rdb)
	if ws.SplitBrain {
		d := ws.SplitBrainDetail
		if d == "" {
			d = "peer or witness reports another primary"
		}
		return fmt.Errorf("geo split-brain fenced: %s (docs/geo-ha-witness.txt)", d)
	}
	if !ws.OK && wc.EffectiveMode(cfg) != "off" {
		return fmt.Errorf("geo witness unhealthy: %s", ws.SplitBrainDetail)
	}
	return nil
}
