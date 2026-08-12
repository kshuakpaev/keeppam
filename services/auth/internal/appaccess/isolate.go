package appaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

const isoRedisPrefix = "keeppam:iso:"

type IsolateConfig struct {
	DockerSock string
	Image      string
	Network    string
}

func IsolateConfigFromEnv() IsolateConfig {
	sock := os.Getenv("KEEPPAM_ISO_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	img := os.Getenv("KEEPPAM_ISO_IMAGE")
	if img == "" {
		img = "keeppam-iso-browser:local"
	}
	netw := os.Getenv("KEEPPAM_ISO_NETWORK")
	if netw == "" {
		netw = "deploy_default"
	}
	return IsolateConfig{DockerSock: sock, Image: img, Network: netw}
}

type IsolateEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
}

func (s *Service) IsolateStart(ctx context.Context, sessionID uuid.UUID, creds assets.TargetCreds, loginURL string) (IsolateEndpoint, error) {
	if cached, ok := s.isoGet(ctx, sessionID); ok {
		if tcpReady(cached.Host, cached.Port, 800*time.Millisecond) {
			return cached, nil
		}
		s.IsolateStop(ctx, sessionID)
	}
	cfg := IsolateConfigFromEnv()
	url := startURL(creds, loginURL)
	name := containerName(sessionID)
	if err := dockerCreateStart(ctx, cfg, name, url); err != nil {
		return IsolateEndpoint{}, err
	}
	ep := IsolateEndpoint{Host: name, Port: 5900, Name: name}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if tcpReady(ep.Host, ep.Port, time.Second) {
			s.isoPut(ctx, sessionID, ep)
			return ep, nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	_ = dockerStop(ctx, cfg, name)
	return IsolateEndpoint{}, fmt.Errorf("isolated browser VNC not ready on %s:5900", name)
}

func (s *Service) IsolateStop(ctx context.Context, sessionID uuid.UUID) {
	cfg := IsolateConfigFromEnv()
	name := containerName(sessionID)
	if cached, ok := s.isoGet(ctx, sessionID); ok && cached.Name != "" {
		name = cached.Name
	}
	_ = dockerStop(ctx, cfg, name)
	if s.rdb != nil {
		_ = s.rdb.Del(ctx, isoRedisPrefix+sessionID.String()).Err()
	}
}

func (s *Service) isoGet(ctx context.Context, id uuid.UUID) (IsolateEndpoint, bool) {
	if s.rdb == nil {
		return IsolateEndpoint{}, false
	}
	raw, err := s.rdb.Get(ctx, isoRedisPrefix+id.String()).Result()
	if err != nil || raw == "" {
		return IsolateEndpoint{}, false
	}
	var ep IsolateEndpoint
	if json.Unmarshal([]byte(raw), &ep) != nil || ep.Host == "" {
		return IsolateEndpoint{}, false
	}
	if ep.Port == 0 {
		ep.Port = 5900
	}
	return ep, true
}

func (s *Service) isoPut(ctx context.Context, id uuid.UUID, ep IsolateEndpoint) {
	if s.rdb == nil {
		return
	}
	b, _ := json.Marshal(ep)
	_ = s.rdb.Set(ctx, isoRedisPrefix+id.String(), b, 12*time.Hour).Err()
}

func containerName(id uuid.UUID) string {
	h := strings.ReplaceAll(id.String(), "-", "")
	if len(h) > 12 {
		h = h[:12]
	}
	return "kp-iso-" + h
}

func startURL(creds assets.TargetCreds, loginURL string) string {
	u := strings.TrimSpace(loginURL)
	if u != "" {
		return u
	}
	port := creds.Asset.Port
	if port <= 0 {
		port = 443
	}
	return fmt.Sprintf("https://%s:%d/", creds.Asset.Address, port)
}

func tcpReady(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func dockerClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				cfg := IsolateConfigFromEnv()
				var d net.Dialer
				return d.DialContext(ctx, "unix", cfg.DockerSock)
			},
		},
	}
}

func dockerCreateStart(ctx context.Context, cfg IsolateConfig, name, startURL string) error {
	if _, err := os.Stat(cfg.DockerSock); err != nil {
		return fmt.Errorf("docker socket %s: %w (mount /var/run/docker.sock into api)", cfg.DockerSock, err)
	}
	body := map[string]any{
		"Image": cfg.Image,
		"Env":   []string{"START_URL=" + startURL},
		"Labels": map[string]string{
			"keeppam.role": "iso-browser",
			"keeppam.name": name,
		},
		"HostConfig": map[string]any{
			"NetworkMode": cfg.Network,
			"AutoRemove":  true,
			"ShmSize":     256 * 1024 * 1024,
		},
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/create?name="+name, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := dockerClient().Do(req)
	if err != nil {
		return fmt.Errorf("docker create: %w", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		_ = dockerStop(ctx, cfg, name)
		delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/v1.43/containers/"+name+"?force=1", nil)
		if delReq != nil {
			if delResp, err := dockerClient().Do(delReq); err == nil {
				_, _ = io.Copy(io.Discard, delResp.Body)
				_ = delResp.Body.Close()
			}
		}
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/create?name="+name, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req2.Header.Set("Content-Type", "application/json")
		resp, err = dockerClient().Do(req2)
		if err != nil {
			return fmt.Errorf("docker create retry: %w", err)
		}
		b, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("docker create %d: %s", resp.StatusCode, truncateISO(string(b), 400))
	}
	startReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/"+name+"/start", nil)
	if err != nil {
		return err
	}
	startResp, err := dockerClient().Do(startReq)
	if err != nil {
		return fmt.Errorf("docker start: %w", err)
	}
	sb, _ := io.ReadAll(startResp.Body)
	_ = startResp.Body.Close()
	if startResp.StatusCode >= 300 {
		return fmt.Errorf("docker start %d: %s", startResp.StatusCode, truncateISO(string(sb), 400))
	}
	return nil
}

func dockerStop(ctx context.Context, cfg IsolateConfig, name string) error {
	_ = cfg
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.43/containers/"+name+"/stop?t=3", nil)
	if err != nil {
		return err
	}
	resp, err := dockerClient().Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return nil
}

func truncateISO(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
