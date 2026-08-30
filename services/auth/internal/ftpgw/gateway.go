package ftpgw

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/filexfer"
	"github.com/keeppam/auth/internal/nativegw"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
)

// Gateway is an FTP proxy: FileZilla/WinSCP speak FTP to KeepPAM; vault creds go to the target.
type Gateway struct {
	addr       string
	publicHost string
	rdb        *redis.Client
	starter    *nativegw.Starter
	assets     *assets.Service
	sessions   *sessionsvc.Service
	audit      *audit.Service
	files      *filexfer.Service

	lnMu     sync.Mutex
	ln       net.Listener
	draining atomic.Bool
	connWG   sync.WaitGroup
}

func New(addr, publicHost string, rdb *redis.Client, starter *nativegw.Starter, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service, files *filexfer.Service) *Gateway {
	return &Gateway{addr: addr, publicHost: publicHost, rdb: rdb, starter: starter, assets: assetsSvc, sessions: sess, audit: aud, files: files}
}

func (g *Gateway) ListenAndServe(ctx context.Context) error {
	if g.addr == "" || g.addr == "off" {
		<-ctx.Done()
		return nil
	}
	ln, err := net.Listen("tcp", g.addr)
	if err != nil {
		return err
	}
	g.lnMu.Lock()
	g.ln = ln
	g.lnMu.Unlock()
	go func() {
		<-ctx.Done()
		_ = g.Close()
	}()
	slog.Info("ftp gateway", "addr", g.addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			if g.draining.Load() {
				g.connWG.Wait()
				return nil
			}
			select {
			case <-ctx.Done():
				g.connWG.Wait()
				return nil
			default:
				continue
			}
		}
		if g.draining.Load() {
			_ = c.Close()
			continue
		}
		g.connWG.Add(1)
		go func(c net.Conn) {
			defer g.connWG.Done()
			g.handleConn(c)
		}(c)
	}
}

func (g *Gateway) Close() error {
	g.draining.Store(true)
	g.lnMu.Lock()
	ln := g.ln
	g.ln = nil
	g.lnMu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

type ftpState struct {
	br     *bufio.Reader
	client net.Conn
	up     net.Conn
	upBr   *bufio.Reader
	user   string
	pass   string
	sess   sessionsvc.Session
	creds  assets.TargetCreds
	pam    store.User
}

func (g *Gateway) handleConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Minute))
	st := &ftpState{br: bufio.NewReader(client), client: client}
	_ = writeFTP(client, "220 KeepPAM FTP gateway")

	ctx := context.Background()
	ip := clientIP(client)

	for {
		line, err := readFTPLine(st.br)
		if err != nil {
			g.endSession(ctx, st, ip)
			return
		}
		cmd, arg := splitFTP(line)
		switch cmd {
		case "USER":
			st.user = strings.TrimSpace(arg)
			_ = writeFTP(client, "331 Password required")
		case "PASS":
			st.pass = arg
			if err := g.login(ctx, st, ip); err != nil {
				_ = writeFTP(client, "530 "+err.Error())
				return
			}
			_ = client.SetDeadline(time.Time{})
			_ = writeFTP(client, "230 Logged on")
		case "QUIT":
			_ = writeFTP(client, "221 Bye")
			g.endSession(ctx, st, ip)
			return
		case "SYST":
			_ = writeFTP(client, "215 UNIX Type: L8")
		case "FEAT":
			_, _ = io.WriteString(client, "211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n211 End\r\n")
		case "TYPE":
			_ = writeFTP(client, "200 Type set")
		case "OPTS", "NOOP", "MODE", "STRU":
			_ = writeFTP(client, "200 OK")
		case "PWD", "XPWD":
			if st.up == nil {
				_ = writeFTP(client, "530 Not logged in")
				continue
			}
			g.relay(st, line)
		case "CWD", "CDUP", "MKD", "RMD", "DELE", "RNFR", "RNTO", "SIZE", "MDTM", "LIST", "NLST", "RETR", "STOR", "PASV", "EPSV":
			if st.up == nil {
				_ = writeFTP(client, "530 Not logged in")
				continue
			}
			if cmd == "PASV" || cmd == "EPSV" {
				g.handlePASV(ctx, st, cmd == "EPSV")
				continue
			}
			if cmd == "STOR" || cmd == "RETR" {
				g.handleTransfer(ctx, st, cmd, arg, line)
				continue
			}
			g.recordCmd(ctx, st, line)
			g.relay(st, line)
		case "PORT", "EPRT":
			_ = writeFTP(client, "502 Active mode disabled; use PASV")
		default:
			if st.up != nil {
				g.relay(st, line)
			} else {
				_ = writeFTP(client, "500 Unknown command")
			}
		}
	}
}

func (g *Gateway) login(ctx context.Context, st *ftpState, ip string) error {
	if id, err := uuid.Parse(strings.TrimSpace(st.user)); err == nil && g.rdb != nil {
		if dbproxy.CheckWireToken(ctx, g.rdb, id, st.pass) {
			row, err := g.sessions.Get(ctx, id)
			if err != nil || row.Protocol != "ftp" {
				return fmt.Errorf("session not found")
			}
			creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
			if err != nil {
				return err
			}
			st.sess = row
			st.creds = creds
			return g.dialUpstream(ctx, st, ip)
		}
	}
	if g.starter == nil {
		return fmt.Errorf("access denied")
	}
	login, hint := nativegw.SplitLogin(st.user)
	u, err := g.starter.Authenticate(ctx, login, st.pass, ip)
	if err != nil {
		return fmt.Errorf("access denied")
	}
	if hint == "" {
		return fmt.Errorf("use USER user+ASSET")
	}
	sess, creds, err := g.starter.Start(ctx, u, "ftp", hint, ip)
	if err != nil {
		return err
	}
	st.pam = u
	st.sess = sess
	st.creds = creds
	return g.dialUpstream(ctx, st, ip)
}

func (g *Gateway) dialUpstream(ctx context.Context, st *ftpState, ip string) error {
	host := st.creds.Asset.Address
	if host == "" {
		host = st.creds.Asset.Hostname
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(st.creds.Asset.Port)), 20*time.Second)
	if err != nil {
		_ = g.sessions.MarkEnded(ctx, st.sess.ID, err.Error())
		return err
	}
	st.up = up
	st.upBr = bufio.NewReader(up)
	if _, _, err := readFTPReply(st.upBr); err != nil {
		_ = up.Close()
		return err
	}
	if err := writeFTP(up, "USER "+st.creds.Account.Username); err != nil {
		return err
	}
	if _, _, err := readFTPReply(st.upBr); err != nil {
		return err
	}
	if err := writeFTP(up, "PASS "+st.creds.Secret); err != nil {
		return err
	}
	code, msg, err := readFTPReply(st.upBr)
	if err != nil {
		return err
	}
	if code >= 400 {
		_ = up.Close()
		st.up = nil
		return fmt.Errorf("upstream login failed: %s", msg)
	}
	_ = g.sessions.MarkActive(ctx, st.sess.ID)
	uid := st.sess.UserID
	_ = g.audit.Record(ctx, &uid, "session.started", "session", st.sess.ID.String(), ip, "ftp", map[string]any{
		"asset": st.creds.Asset.Name, "via": "ftp-gateway",
	})
	return nil
}

func (g *Gateway) relay(st *ftpState, line string) {
	if err := writeFTP(st.up, line); err != nil {
		return
	}
	code, msg, err := readFTPReply(st.upBr)
	if err != nil {
		_ = writeFTP(st.client, "426 Data connection error")
		return
	}
	_ = writeFTP(st.client, fmt.Sprintf("%d %s", code, msg))
}

func (g *Gateway) handlePASV(ctx context.Context, st *ftpState, epsv bool) {
	g.recordCmd(ctx, st, map[bool]string{true: "EPSV", false: "PASV"}[epsv])
	if err := writeFTP(st.up, "PASV"); err != nil {
		_ = writeFTP(st.client, "425 PASV failed")
		return
	}
	code, msg, err := readFTPReply(st.upBr)
	if err != nil || code >= 400 {
		_ = writeFTP(st.client, "425 PASV failed")
		return
	}
	host, port, err := parsePASV(msg)
	if err != nil {
		_ = writeFTP(st.client, "425 PASV parse failed")
		return
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		_ = writeFTP(st.client, "425 listen failed")
		return
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	pub := g.publicHost
	if pub == "" {
		if h, _, err := net.SplitHostPort(st.client.LocalAddr().String()); err == nil {
			pub = h
		}
	}
	if pub == "" || pub == "0.0.0.0" || pub == "::" {
		pub = "127.0.0.1"
	}
	if epsv {
		_ = writeFTP(st.client, fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)", tcpAddr.Port))
	} else {
		_ = writeFTP(st.client, formatPASV(pub, tcpAddr.Port))
	}
	go func() {
		defer ln.Close()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
		dc, err := ln.Accept()
		if err != nil {
			return
		}
		defer dc.Close()
		upData, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 20*time.Second)
		if err != nil {
			return
		}
		defer upData.Close()
		st.client.SetDeadline(time.Time{}) //nolint:errcheck
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(dc, upData); done <- struct{}{} }()
		go func() { _, _ = io.Copy(upData, dc); done <- struct{}{} }()
		<-done
	}()
}

func (g *Gateway) handleTransfer(ctx context.Context, st *ftpState, cmd, arg, line string) {
	g.recordCmd(ctx, st, line)
	g.relay(st, line)
	_ = cmd
	_ = arg
}

func (g *Gateway) recordCmd(ctx context.Context, st *ftpState, line string) {
	if st.sess.ID == uuid.Nil {
		return
	}
	_ = g.sessions.AddEvent(ctx, st.sess.ID, "ftp", map[string]any{"command": truncate(line, 512)})
}

func (g *Gateway) endSession(ctx context.Context, st *ftpState, ip string) {
	if st.up != nil {
		_ = st.up.Close()
		st.up = nil
	}
	if st.sess.ID == uuid.Nil {
		return
	}
	_ = g.sessions.MarkEnded(ctx, st.sess.ID, "")
	uid := st.sess.UserID
	_ = g.audit.Record(ctx, &uid, "session.ended", "session", st.sess.ID.String(), ip, "ftp", nil)
}

func writeFTP(w io.Writer, line string) error {
	_, err := io.WriteString(w, line+"\r\n")
	return err
}

func readFTPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func splitFTP(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
}

func readFTPReply(br *bufio.Reader) (int, string, error) {
	for {
		line, err := readFTPLine(br)
		if err != nil {
			return 0, "", err
		}
		if len(line) >= 4 && line[3] == ' ' {
			code, _ := strconv.Atoi(line[:3])
			return code, strings.TrimSpace(line[4:]), nil
		}
		if len(line) >= 3 && line[3] != '-' {
			code, _ := strconv.Atoi(line[:3])
			return code, strings.TrimSpace(line[3:]), nil
		}
	}
}

func parsePASV(msg string) (host string, port int, err error) {
	i := strings.IndexByte(msg, '(')
	j := strings.IndexByte(msg, ')')
	if i < 0 || j <= i {
		return "", 0, fmt.Errorf("no paren")
	}
	parts := strings.Split(msg[i+1:j], ",")
	if len(parts) < 6 {
		return "", 0, fmt.Errorf("need 6 fields")
	}
	p1, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
	host = strings.Join(parts[0:4], ".")
	return host, p1*256 + p2, nil
}

func formatPASV(host string, port int) string {
	host = strings.ReplaceAll(host, ".", ",")
	p1, p2 := port/256, port%256
	return fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)", host, p1, p2)
}

func clientIP(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
