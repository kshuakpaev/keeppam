package rdpgw

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
)

const tokenPrefix = "keeppam:rdp:"

// Broker launches per-session freerdp-proxy (optional) and issues native connect info.
type Broker struct {
	PublicHost string // hostname clients put in .rdp (e.g. pam.example.com)
	ListenHost string // bind host for dynamic ports (default 0.0.0.0)
	ProxyBin   string // path to freerdp-proxy; empty = tokens/.rdp only
	CertFile   string
	KeyFile    string
	WorkDir    string
	rdb        *redis.Client
	assets     *assets.Service
	sessions   *sessionsvc.Service

	mu      sync.Mutex
	running map[uuid.UUID]*proxyProc
}

type proxyProc struct {
	cmd  *exec.Cmd
	port int
	dir  string
}

func NewBroker(publicHost, proxyBin, cert, key, workDir string, rdb *redis.Client, assetsSvc *assets.Service, sess *sessionsvc.Service) *Broker {
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "keeppam-rdp")
	}
	return &Broker{
		PublicHost: publicHost,
		ListenHost: "0.0.0.0",
		ProxyBin:   strings.TrimSpace(proxyBin),
		CertFile:   cert,
		KeyFile:    key,
		WorkDir:    workDir,
		rdb:        rdb,
		assets:     assetsSvc,
		sessions:   sess,
		running:    map[uuid.UUID]*proxyProc{},
	}
}

func (b *Broker) Enabled() bool {
	return b != nil && b.PublicHost != "" && b.PublicHost != "off"
}

func (b *Broker) ProxyAvailable() bool {
	return b != nil && b.ProxyBin != "" && b.ProxyBin != "off"
}

func IssueToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, ttl time.Duration) (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	tok := fmt.Sprintf("%x", buf)
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return tok, rdb.Set(ctx, tokenPrefix+sessionID.String(), tok, ttl).Err()
}

func (b *Broker) ValidateToken(ctx context.Context, sessionID uuid.UUID, tok string) bool {
	if b == nil || b.rdb == nil || tok == "" {
		return false
	}
	v, err := b.rdb.Get(ctx, tokenPrefix+sessionID.String()).Result()
	return err == nil && v == tok
}

// ConnectInfo is returned to the portal after session create when native RDP is allowed.
type ConnectInfo struct {
	Token    string `json:"rdp_token"`
	Addr     string `json:"rdp_addr"`
	Port     int    `json:"rdp_port"`
	User     string `json:"rdp_user"`
	Hint     string `json:"rdp_hint"`
	File     string `json:"rdp_file"`
	ProxyOK  bool   `json:"rdp_proxy"`
	Filename string `json:"rdp_filename"`
}

// Prepare starts optional freerdp-proxy and builds mstsc/.rdp connect info.
func (b *Broker) Prepare(ctx context.Context, row sessionsvc.Session, snap *policy.Snapshot, ttl time.Duration) (*ConnectInfo, error) {
	if !b.Enabled() {
		return nil, fmt.Errorf("native RDP broker disabled")
	}
	rdp := policy.RDPRedir{}
	if snap != nil {
		rdp = snap.RDP()
	}
	if !rdp.Native {
		return nil, fmt.Errorf("rdp_native not enabled in access policy")
	}
	tok, err := IssueToken(ctx, b.rdb, row.ID, ttl)
	if err != nil {
		return nil, err
	}
	creds, err := b.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
	if err != nil {
		return nil, err
	}
	port := b.PortOf(row.ID)
	proxyOK := port > 0
	if !proxyOK && b.ProxyAvailable() {
		p, err := b.startProxy(ctx, row.ID, creds, rdp)
		if err != nil {
			slog.Warn("rdp freerdp-proxy", "err", err, "session", row.ID.String())
		} else {
			port = p
			proxyOK = true
		}
	}
	host := b.PublicHost
	if host == "" {
		host = "127.0.0.1"
	}
	addr := host
	if port > 0 {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	file := BuildRDPFile(host, port, row.ID.String(), rdp, row.RDPWidth, row.RDPHeight, RemoteAppOpts{
		Program: creds.Asset.RDPRemoteApp,
		Dir:     creds.Asset.RDPRemoteAppDir,
		Args:    creds.Asset.RDPRemoteAppArgs,
	})
	hint := "mstsc: скачайте .rdp (без пароля цели). Нужен freerdp-proxy на PAM (KEEPPAM_RDP_PROXY_BIN)."
	if proxyOK {
		hint = fmt.Sprintf("mstsc /v:%s — пароль цели не нужен (inject на шлюзе). Token=%s для аудита.", addr, tok[:8]+"…")
	}
	return &ConnectInfo{
		Token:    tok,
		Addr:     addr,
		Port:     port,
		User:     row.ID.String(),
		Hint:     hint,
		File:     file,
		ProxyOK:  proxyOK,
		Filename: fmt.Sprintf("keeppam-%s.rdp", row.ID.String()[:8]),
	}, nil
}

func (b *Broker) Stop(sessionID uuid.UUID) {
	if b == nil {
		return
	}
	b.mu.Lock()
	p := b.running[sessionID]
	delete(b.running, sessionID)
	b.mu.Unlock()
	if p == nil {
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

func (b *Broker) PortOf(sessionID uuid.UUID) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if p := b.running[sessionID]; p != nil {
		return p.port
	}
	return 0
}

func (b *Broker) startProxy(_ context.Context, sessionID uuid.UUID, creds assets.TargetCreds, rdp policy.RDPRedir) (int, error) {
	b.Stop(sessionID)
	ln, err := net.Listen("tcp", net.JoinHostPort(b.ListenHost, "0"))
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	dir := filepath.Join(b.WorkDir, sessionID.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	iniPath := filepath.Join(dir, "proxy.ini")
	ini := buildProxyINI(port, creds, rdp, b.CertFile, b.KeyFile)
	if err := os.WriteFile(iniPath, []byte(ini), 0o600); err != nil {
		return 0, err
	}
	cmd := exec.Command(b.ProxyBin, iniPath) //nolint:gosec // configured admin binary
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return 0, err
	}
	b.mu.Lock()
	b.running[sessionID] = &proxyProc{cmd: cmd, port: port, dir: dir}
	b.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		b.mu.Lock()
		if cur := b.running[sessionID]; cur != nil && cur.cmd == cmd {
			delete(b.running, sessionID)
		}
		b.mu.Unlock()
		_ = os.RemoveAll(dir)
		_ = b.sessions.MarkEnded(context.Background(), sessionID, "rdp proxy exited")
	}()
	return port, nil
}

func buildProxyINI(listenPort int, creds assets.TargetCreds, rdp policy.RDPRedir, cert, key string) string {
	host := creds.Asset.Address
	if host == "" {
		host = creds.Asset.Hostname
	}
	tport := creds.Asset.Port
	if tport <= 0 {
		tport = 3389
	}
	var b strings.Builder
	b.WriteString("[Server]\n")
	b.WriteString(fmt.Sprintf("Host=0.0.0.0\nPort=%d\n", listenPort))
	b.WriteString("\n[Target]\n")
	b.WriteString("FixedTarget=true\n")
	b.WriteString(fmt.Sprintf("Host=%s\nPort=%d\n", host, tport))
	b.WriteString(fmt.Sprintf("User=%s\nPassword=%s\n", escapeINI(creds.Account.Username), escapeINI(creds.Secret)))
	if cert != "" && key != "" {
		b.WriteString("\n[Certificates]\n")
		b.WriteString(fmt.Sprintf("CertificateFile=%s\nPrivateKeyFile=%s\n", cert, key))
	}
	// Channel policy mirrors DLP-strict defaults.
	b.WriteString("\n[Channels]\n")
	if !rdp.Clipboard {
		b.WriteString("cliprdr=false\n")
	}
	if !rdp.Drive {
		b.WriteString("rdpdr=false\n")
	}
	if !rdp.Printer {
		b.WriteString("rail_printing=false\n")
	}
	return b.String()
}

func escapeINI(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}

// NormalizeSize clamps RDP desktop size; 0 means use defaults (1280×800).
func NormalizeSize(width, height int) (int, int) {
	if width <= 0 || height <= 0 {
		return 1280, 800
	}
	if width < 640 {
		width = 640
	}
	if width > 7680 {
		width = 7680
	}
	if height < 480 {
		height = 480
	}
	if height > 4320 {
		height = 4320
	}
	return width, height
}

// RemoteAppOpts is optional RDS RemoteApp (RAIL) for .rdp / guac.
type RemoteAppOpts struct {
	Program string
	Dir     string
	Args    string
}

// BuildRDPFile returns an .rdp body for mstsc (NLA to proxy disabled; creds injected by freerdp-proxy).
func BuildRDPFile(host string, port int, sessionUser string, rdp policy.RDPRedir, width, height int, remote ...RemoteAppOpts) string {
	addr := host
	if port > 0 {
		addr = fmt.Sprintf("%s:%d", host, port)
	}
	var b strings.Builder
	b.WriteString("full address:s:" + addr + "\n")
	b.WriteString("username:s:" + sessionUser + "\n")
	b.WriteString("prompt for credentials:i:0\n")
	b.WriteString("authentication level:i:0\n")
	b.WriteString("negotiate security layer:i:0\n")
	b.WriteString("enablecredsspsupport:i:0\n")
	b.WriteString("autoreconnection enabled:i:0\n")
	if rdp.Clipboard {
		b.WriteString("redirectclipboard:i:1\n")
	} else {
		b.WriteString("redirectclipboard:i:0\n")
	}
	if rdp.Drive {
		b.WriteString("drivestoredirect:s:*\n")
	} else {
		b.WriteString("drivestoredirect:s:\n")
	}
	if rdp.Printer {
		b.WriteString("redirectprinters:i:1\n")
	} else {
		b.WriteString("redirectprinters:i:0\n")
	}
	var ra RemoteAppOpts
	if len(remote) > 0 {
		ra = remote[0]
	}
	if prog := strings.TrimSpace(ra.Program); prog != "" {
		b.WriteString("remoteapplicationmode:i:1\n")
		b.WriteString("remoteapplicationprogram:s:" + escapeINI(prog) + "\n")
		if d := strings.TrimSpace(ra.Dir); d != "" {
			b.WriteString("remoteapplicationdir:s:" + escapeINI(d) + "\n")
		}
		if a := strings.TrimSpace(ra.Args); a != "" {
			b.WriteString("remoteapplicationcmdline:s:" + escapeINI(a) + "\n")
		}
		b.WriteString("disableremoteappcapscheck:i:1\n")
	}
	w, h := NormalizeSize(width, height)
	b.WriteString(fmt.Sprintf("desktopwidth:i:%d\n", w))
	b.WriteString(fmt.Sprintf("desktopheight:i:%d\n", h))
	b.WriteString("session bpp:i:24\n")
	return b.String()
}
