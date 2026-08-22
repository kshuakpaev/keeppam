package tn3270gw

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/tn3270"
)

// Gateway accepts native TN3270 clients (x3270/c3270): negotiate → login screen → host bridge.
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
	slog.Info("tn3270 gateway", "addr", g.addr)
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
	ctx := context.Background()

	if err := tn3270.NegotiateServer(client, "IBM-3278-2"); err != nil {
		slog.Debug("tn3270 negotiate client", "err", err)
		return
	}
	user, pass, err := tn3270.LoginScreen(client, "KeepPAM TN3270 gateway", tn3270.CP037)
	if err != nil {
		slog.Debug("tn3270 login", "err", err)
		return
	}
	sessionID, err := uuid.Parse(user)
	if err != nil || !dbproxy.CheckWireToken(ctx, g.rdb, sessionID, pass) {
		_ = sendMsg(client, "ACCESS DENIED")
		return
	}

	row, err := g.sessions.Get(ctx, sessionID)
	if err != nil || row.Protocol != "tn3270" {
		_ = sendMsg(client, "SESSION NOT FOUND")
		return
	}
	if row.Status != "pending" && row.Status != "active" {
		_ = sendMsg(client, "SESSION NOT STARTABLE")
		return
	}
	if row.WaitingSupervisor || row.IsWaitingSupervisor() {
		_ = sendMsg(client, "WAITING SUPERVISOR")
		return
	}

	creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
	if err != nil {
		_ = sendMsg(client, err.Error())
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		return
	}

	hostName := creds.Asset.Address
	if hostName == "" {
		hostName = creds.Asset.Hostname
	}
	up, err := tn3270.Dial(hostName, creds.Asset.Port)
	if err != nil {
		_ = sendMsg(client, err.Error())
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		_ = g.audit.Record(ctx, &row.UserID, "session.failed", "session", sessionID.String(), clientIP(client), "", map[string]any{"error": err.Error()})
		return
	}
	defer up.Close()

	cp := tn3270.NormalizeCodepage(creds.Asset.Tn3270Codepage)
	termType := tn3270.ResolveTermType(creds.Asset.Tn3270TerminalType, cp)

	if err := tn3270.NegotiateClient(up, termType); err != nil {
		_ = sendMsg(client, "HOST NEGOTIATE FAILED")
		_ = g.sessions.MarkEnded(ctx, sessionID, err.Error())
		return
	}

	_ = g.sessions.MarkActive(ctx, sessionID)
	_ = g.audit.Record(ctx, &row.UserID, "session.started", "session", sessionID.String(), clientIP(client), "", map[string]any{
		"asset": creds.Asset.Name, "account": creds.Account.Username, "via": "tn3270-wire",
		"tn3270_codepage": string(cp), "tn3270_term": termType,
	})

	hbStop := make(chan struct{})
	go sessionsvc.Heartbeat(ctx, g.sessions, sessionID, 30*time.Second, hbStop)
	defer close(hbStop)

	_ = sendMsg(client, "Connecting to "+creds.Asset.Name+"...")
	time.Sleep(200 * time.Millisecond)

	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = tn3270.Bridge(bridgeCtx, client, up, tn3270.BridgeOpts{
		RecordingPath: row.RecordingPath,
		SessionID:     sessionID,
		Sessions:      g.sessions,
		Codepage:      cp,
	})

	_ = g.sessions.MarkEnded(ctx, sessionID, "")
	_ = g.audit.Record(ctx, &row.UserID, "session.ended", "session", sessionID.String(), clientIP(client), "", nil)
}

func sendMsg(c net.Conn, msg string) error {
	payload := []byte{0xF5, 0xC3}
	payload = append(payload, 0x11, 0x40, 0x40, 0x1D, 0x60)
	payload = append(payload, tn3270.EncodeEBCDIC(msg)...)
	_, err := c.Write(tn3270.FrameEOR(payload))
	return err
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