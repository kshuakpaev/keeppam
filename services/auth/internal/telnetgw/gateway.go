package telnetgw

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/sshproxy"
	"github.com/keeppam/auth/internal/telnet"
)

// Gateway accepts native Telnet clients with wire auth (session UUID + token).
type Gateway struct {
	addr     string
	rdb      *redis.Client
	assets   *assets.Service
	sessions *sessionsvc.Service
	audit    *audit.Service

	lnMu     sync.Mutex
	ln       net.Listener
	draining atomic.Bool
	connWG   sync.WaitGroup
}

func New(addr string, rdb *redis.Client, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service) *Gateway {
	return &Gateway{addr: addr, rdb: rdb, assets: assetsSvc, sessions: sess, audit: aud}
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
	slog.Info("telnet gateway", "addr", g.addr)
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

func (g *Gateway) handleConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(60 * time.Second))
	br := bufio.NewReader(client)

	_, _ = io.WriteString(client, "KeepPAM Telnet gateway\r\nlogin: ")
	userLine, err := readLine(br)
	if err != nil {
		return
	}
	_, _ = io.WriteString(client, "Password: ")
	passLine, err := readLine(br)
	if err != nil {
		return
	}
	_, _ = io.WriteString(client, "\r\n")

	sessionID, err := uuid.Parse(strings.TrimSpace(userLine))
	if err != nil {
		_, _ = io.WriteString(client, "access denied\r\n")
		return
	}
	ctx := context.Background()
	if !dbproxy.CheckWireToken(ctx, g.rdb, sessionID, strings.TrimSpace(passLine)) {
		_, _ = io.WriteString(client, "access denied\r\n")
		return
	}

	row, err := g.sessions.Get(ctx, sessionID)
	if err != nil || row.Protocol != "telnet" {
		_, _ = io.WriteString(client, "session not found\r\n")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		_, _ = io.WriteString(client, "session not startable\r\n")
		return
	}
	if row.WaitingSupervisor || row.IsWaitingSupervisor() {
		_, _ = io.WriteString(client, "waiting for supervisor\r\n")
		return
	}

	creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
	if err != nil {
		_, _ = io.WriteString(client, err.Error()+"\r\n")
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		return
	}

	rec, err := sshproxy.NewRecorder(row.RecordingPath, 120, 40, creds.Asset.Name)
	if err != nil {
		_, _ = io.WriteString(client, "recorder failed\r\n")
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		return
	}
	if row.PolicySnapshot != nil {
		rec.SetCharset(row.PolicySnapshot.TerminalCharset)
	} else {
		rec.SetCharset(creds.Asset.TerminalCharset)
	}

	host := creds.Asset.Address
	if host == "" {
		host = creds.Asset.Hostname
	}
	up, err := telnet.Dial(ctx, host, creds.Asset.Port)
	if err != nil {
		_ = rec.Close()
		_, _ = io.WriteString(client, err.Error()+"\r\n")
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		_ = g.audit.Record(ctx, &row.UserID, "session.failed", "session", sessionID.String(), clientIP(client), "", map[string]any{"error": err.Error()})
		return
	}

	bridge, err := telnet.StartBridge(up, 120, 40, rec, telnet.SessionOpts{
		Username: creds.Account.Username, Password: creds.Secret,
		InjectLogin: true, TermType: "xterm-256color",
	})
	if err != nil {
		_ = up.Close()
		_ = rec.Close()
		_, _ = io.WriteString(client, err.Error()+"\r\n")
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		return
	}
	defer bridge.Close()

	_ = client.SetDeadline(time.Time{})
	_ = g.sessions.MarkActive(ctx, sessionID)
	_ = g.audit.Record(ctx, &row.UserID, "session.started", "session", sessionID.String(), clientIP(client), "", map[string]any{
		"asset": creds.Asset.Name, "account": creds.Account.Username, "via": "telnet-wire",
	})

	hbStop := make(chan struct{})
	go sessionsvc.Heartbeat(ctx, g.sessions, sessionID, 30*time.Second, hbStop)
	defer close(hbStop)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = bridge.CopyOutput(client)
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				if _, werr := bridge.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		bridge.Close()
	}()

	<-done
	_ = g.sessions.MarkEnded(ctx, sessionID, "")
	_ = g.audit.Record(ctx, &row.UserID, "session.ended", "session", sessionID.String(), clientIP(client), "", nil)
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
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
