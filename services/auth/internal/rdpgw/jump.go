package rdpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/policy"
)

// JumpConfig launches a per-session Xvfb+xfreerdp container so mstsc and guacd
// share one target login (recordable .guac + optional drive staging).
type JumpConfig struct {
	Image         string
	DockerSock    string
	Network       string
	GuacdAddr     string
	RecordingsDir string
}

func JumpConfigFromEnv(recordingsDir, guacdAddr string) JumpConfig {
	img := strings.TrimSpace(os.Getenv("KEEPPAM_RDP_JUMP_IMAGE"))
	if img == "" {
		img = "keeppam-rdp-jump:local"
	}
	sock := strings.TrimSpace(os.Getenv("KEEPPAM_ISO_DOCKER_SOCK"))
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	netw := strings.TrimSpace(os.Getenv("KEEPPAM_ISO_NETWORK"))
	if netw == "" {
		netw = "deploy_default"
	}
	return JumpConfig{
		Image: img, DockerSock: sock, Network: netw,
		GuacdAddr: guacdAddr, RecordingsDir: recordingsDir,
	}
}

func (j JumpConfig) Enabled() bool {
	img := strings.TrimSpace(j.Image)
	return img != "" && !strings.EqualFold(img, "off")
}

func jumpContainerName(id uuid.UUID) string {
	h := strings.ReplaceAll(id.String(), "-", "")
	if len(h) > 12 {
		h = h[:12]
	}
	return "kp-rdp-" + h
}

func jumpDrivePath(recordingsDir string, sessionID uuid.UUID, snap *policy.Snapshot) (drivePath string, clipboard bool) {
	rdp := policy.RDPRedir{}
	ft := policy.FileTransferDeny
	if snap != nil {
		rdp = snap.RDP()
		ft = snap.EffectiveFileTransfer()
	}
	clipboard = rdp.Clipboard
	root := strings.TrimSpace(recordingsDir)
	if root == "" {
		return "", clipboard
	}
	if rdp.Drive {
		return filepath.Join(root, "rdp-drive", sessionID.String()), clipboard
	}
	if rdp.Clipboard && !policy.FileTransferDenied(ft) {
		return filepath.Join(root, "rdp-clipboard", sessionID.String()), clipboard
	}
	return "", clipboard
}

func (b *Broker) startJump(ctx context.Context, sessionID uuid.UUID, creds assets.TargetCreds, snap *policy.Snapshot, width, height int) (int, error) {
	if b == nil || !b.Jump.Enabled() {
		return 0, fmt.Errorf("rdp jump disabled")
	}
	if _, err := os.Stat(b.Jump.DockerSock); err != nil {
		return 0, fmt.Errorf("docker socket %s: %w", b.Jump.DockerSock, err)
	}
	b.Stop(sessionID)

	host := strings.TrimSpace(creds.Asset.Address)
	if host == "" {
		host = strings.TrimSpace(creds.Asset.Hostname)
	}
	if host == "" {
		return 0, fmt.Errorf("rdp jump: asset has no address")
	}
	tport := creds.Asset.Port
	if tport <= 0 {
		tport = 3389
	}
	w, h := NormalizeSize(width, height)
	name := jumpContainerName(sessionID)
	drive, clip := jumpDrivePath(b.recordingsDir(), sessionID, snap)
	if drive != "" {
		_ = os.MkdirAll(drive, 0o750)
	}
	env := []string{
		"RDP_HOST=" + host,
		fmt.Sprintf("RDP_PORT=%d", tport),
		"RDP_USER=" + creds.Account.Username,
		"RDP_PASSWORD=" + creds.Secret,
		fmt.Sprintf("RDP_WIDTH=%d", w),
		fmt.Sprintf("RDP_HEIGHT=%d", h),
	}
	if drive != "" {
		env = append(env, "DRIVE_PATH="+drive)
	}
	if clip {
		env = append(env, "CLIPBOARD=1")
	}
	if app := strings.TrimSpace(creds.Asset.RDPRemoteApp); app != "" {
		env = append(env, "REMOTE_APP="+app)
		if d := strings.TrimSpace(creds.Asset.RDPRemoteAppDir); d != "" {
			env = append(env, "REMOTE_APP_DIR="+d)
		}
		if a := strings.TrimSpace(creds.Asset.RDPRemoteAppArgs); a != "" {
			env = append(env, "REMOTE_APP_ARGS="+a)
		}
	}

	hostCfg := map[string]any{
		"NetworkMode": b.resolveNetwork(ctx),
		"AutoRemove":  true,
		"ShmSize":     256 * 1024 * 1024,
		"PortBindings": map[string]any{
			"3389/tcp": []map[string]string{{"HostPort": "0"}},
		},
	}
	if vol, bind := b.recordingsMount(ctx); vol != "" {
		hostCfg["Mounts"] = []map[string]any{{
			"Type": "volume", "Source": vol, "Target": "/tmp/recordings",
		}}
	} else if bind != "" {
		hostCfg["Binds"] = []string{bind + ":/tmp/recordings"}
	}

	body := map[string]any{
		"Image":        b.Jump.Image,
		"Env":          env,
		"ExposedPorts": map[string]any{"3389/tcp": map[string]any{}, "5900/tcp": map[string]any{}},
		"Labels": map[string]string{
			"keeppam.role":    "rdp-jump",
			"keeppam.session": sessionID.String(),
		},
		"HostConfig": hostCfg,
	}
	if err := dockerCreateStart(ctx, b.Jump.DockerSock, name, body); err != nil {
		return 0, err
	}

	deadline := time.Now().Add(25 * time.Second)
	var hostPort int
	for time.Now().Before(deadline) {
		if tcpReady(name, 5900, time.Second) {
			if p, err := dockerPublishedPort(ctx, b.Jump.DockerSock, name, 3389); err == nil && p > 0 {
				hostPort = p
				break
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	if hostPort == 0 {
		_ = dockerStop(ctx, b.Jump.DockerSock, name)
		return 0, fmt.Errorf("rdp jump %s: VNC/RDP not ready", name)
	}

	var stopRec func()
	var recErr error
	for i := 0; i < 8; i++ {
		stopRec, recErr = b.startVNCRecorder(sessionID, name, 5900, w, h)
		if recErr == nil {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if recErr != nil {
		_ = dockerStop(ctx, b.Jump.DockerSock, name)
		return 0, fmt.Errorf("rdp jump recorder: %w", recErr)
	}

	b.mu.Lock()
	b.running[sessionID] = &proxyProc{
		port:     hostPort,
		jumpName: name,
		recStop:  stopRec,
	}
	b.mu.Unlock()

	_ = b.sessions.MarkActive(context.Background(), sessionID)
	_ = b.sessions.AddEvent(context.Background(), sessionID, "rdp_jump_started", map[string]any{
		"container": name, "rdp_port": hostPort, "vnc": name + ":5900",
	})
	go func() {
		waitDockerExit(b.Jump.DockerSock, name)
		b.mu.Lock()
		cur := b.running[sessionID]
		if cur == nil || cur.jumpName != name {
			b.mu.Unlock()
			return
		}
		delete(b.running, sessionID)
		stop := cur.recStop
		b.mu.Unlock()
		if stop != nil {
			stop()
		}
		_ = b.sessions.MarkEnded(context.Background(), sessionID, "rdp jump exited")
	}()
	return hostPort, nil
}

func (b *Broker) resolveNetwork(ctx context.Context) string {
	if n := strings.TrimSpace(os.Getenv("KEEPPAM_ISO_NETWORK")); n != "" {
		return n
	}
	host, _ := os.Hostname()
	raw, err := dockerJSON(ctx, b.Jump.DockerSock, http.MethodGet, "/containers/"+host+"/json", nil)
	if err == nil {
		var ins struct {
			NetworkSettings struct {
				Networks map[string]json.RawMessage `json:"Networks"`
			} `json:"NetworkSettings"`
		}
		if json.Unmarshal(raw, &ins) == nil {
			for name := range ins.NetworkSettings.Networks {
				if name != "" && name != "none" && name != "host" {
					return name
				}
			}
		}
	}
	if b.Jump.Network != "" {
		return b.Jump.Network
	}
	return "deploy_default"
}

func (b *Broker) recordingsDir() string {
	if b.Jump.RecordingsDir != "" {
		return b.Jump.RecordingsDir
	}
	if b.sessions != nil {
		return b.sessions.RecordingsDir()
	}
	return ""
}

func (b *Broker) recordingsMount(ctx context.Context) (volumeName, bindSrc string) {
	if v := strings.TrimSpace(os.Getenv("KEEPPAM_RECORDINGS_VOLUME")); v != "" {
		return v, ""
	}
	dest := b.recordingsDir()
	if dest == "" {
		dest = "/tmp/recordings"
	}
	host, _ := os.Hostname()
	raw, err := dockerJSON(ctx, b.Jump.DockerSock, http.MethodGet, "/containers/"+host+"/json", nil)
	if err != nil {
		return "", dest
	}
	var ins struct {
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if json.Unmarshal(raw, &ins) != nil {
		return "", dest
	}
	for _, m := range ins.Mounts {
		if filepath.Clean(m.Destination) != filepath.Clean(dest) {
			continue
		}
		if strings.EqualFold(m.Type, "volume") && m.Name != "" {
			return m.Name, ""
		}
		if m.Source != "" {
			return "", m.Source
		}
	}
	return "", dest
}

func dockerClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

func dockerJSON(ctx context.Context, sock, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker/v1.43"+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := dockerClient(sock).Do(req)
	if err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("docker %s %s: %d %s", method, path, resp.StatusCode, truncateISO(string(b), 400))
	}
	return b, nil
}

func dockerCreateStart(ctx context.Context, sock, name string, spec map[string]any) error {
	raw, _ := json.Marshal(spec)
	_, err := dockerJSON(ctx, sock, http.MethodPost, "/containers/create?name="+name, raw)
	if err != nil {
		if strings.Contains(err.Error(), " 409 ") {
			_ = dockerStop(ctx, sock, name)
			delCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			_, _ = dockerJSON(delCtx, sock, http.MethodDelete, "/containers/"+name+"?force=1", nil)
			cancel()
			_, err = dockerJSON(ctx, sock, http.MethodPost, "/containers/create?name="+name, raw)
		}
		if err != nil {
			return fmt.Errorf("docker create: %w", err)
		}
	}
	if _, err := dockerJSON(ctx, sock, http.MethodPost, "/containers/"+name+"/start", nil); err != nil {
		return fmt.Errorf("docker start: %w", err)
	}
	return nil
}

func dockerStop(ctx context.Context, sock, name string) error {
	_, err := dockerJSON(ctx, sock, http.MethodPost, "/containers/"+name+"/stop?t=3", nil)
	return err
}

func dockerPublishedPort(ctx context.Context, sock, name string, containerPort int) (int, error) {
	raw, err := dockerJSON(ctx, sock, http.MethodGet, "/containers/"+name+"/json", nil)
	if err != nil {
		return 0, err
	}
	var ins struct {
		NetworkSettings struct {
			Ports map[string][]struct {
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(raw, &ins); err != nil {
		return 0, err
	}
	key := fmt.Sprintf("%d/tcp", containerPort)
	for _, p := range ins.NetworkSettings.Ports[key] {
		n, err := strconv.Atoi(p.HostPort)
		if err == nil && n > 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("no host port for %s", key)
}

func waitDockerExit(sock, name string) {
	// Wait until the container is gone (AutoRemove) or has stopped.
	for i := 0; i < 3600; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := dockerJSON(ctx, sock, http.MethodGet, "/containers/"+name+"/json", nil)
		cancel()
		if err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func tcpReady(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func truncateISO(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
