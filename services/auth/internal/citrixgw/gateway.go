package citrixgw

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/citrix"
	"github.com/keeppam/auth/internal/dbproxy"
	"github.com/keeppam/auth/internal/pcapx"
	"github.com/keeppam/auth/internal/sessionsvc"
)

// Gateway is a SOCKS5 proxy for Citrix ICA/CGP (session UUID + wire token auth).
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
	slog.Info("citrix socks gateway", "addr", g.addr)
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
			g.handle(c)
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

func (g *Gateway) handle(client net.Conn) {
	ctx := context.Background()
	var sessionID uuid.UUID
	var row sessionsvc.Session
	var creds assets.TargetCreds

	tap := &citrix.Tap{}
	var pcapF *os.File
	err := citrix.ServeSOCKS(client,
		func(user, pass string) bool {
			id, err := uuid.Parse(strings.TrimSpace(user))
			if err != nil || !dbproxy.CheckWireToken(ctx, g.rdb, id, pass) {
				return false
			}
			s, err := g.sessions.Get(ctx, id)
			if err != nil || s.Protocol != "citrix" {
				return false
			}
			if s.Status != "pending" && s.Status != "active" {
				return false
			}
			if s.WaitingSupervisor || s.IsWaitingSupervisor() {
				return false
			}
			c, err := g.assets.GetTargetCreds(ctx, s.AssetID, s.AccountID)
			if err != nil {
				return false
			}
			sessionID = id
			row = s
			creds = c
			return true
		},
		func(user, host string, port int) bool {
			if sessionID == uuid.Nil {
				return false
			}
			return destAllowed(creds.Asset, host, port)
		},
		func(user, host string, port int) {
			_ = g.sessions.MarkActive(ctx, sessionID)
			_ = g.audit.Record(ctx, &row.UserID, "session.started", "session", sessionID.String(), clientIP(client), "", map[string]any{
				"asset": creds.Asset.Name, "via": "citrix-socks", "dest": host, "port": port,
			})
			_ = g.sessions.AddEvent(ctx, sessionID, "citrix_connect", map[string]any{
				"host": host, "port": port, "via": "socks5",
			})
			appendRec(row.RecordingPath, map[string]any{
				"t": time.Now().UTC().Format(time.RFC3339Nano),
				"event": "connect", "host": host, "port": port,
			})
			if row.RecordingPath == "" {
				return
			}
			pcapPath := recordingPCAP(row.RecordingPath)
			_ = os.MkdirAll(filepath.Dir(pcapPath), 0o750)
			f, err := os.OpenFile(pcapPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
			if err != nil {
				return
			}
			lw, err := pcapx.NewLiveWriter(f, 1081, uint16(port))
			if err != nil {
				_ = f.Close()
				return
			}
			pcapF = f
			tap.Client = lw.Client()
			tap.Server = lw.Server()
		},
		func(user, host string, port int, bytesUp, bytesDown int64) {
			_ = g.sessions.AddEvent(ctx, sessionID, "citrix_disconnect", map[string]any{
				"host": host, "port": port, "bytes_up": bytesUp, "bytes_down": bytesDown, "via": "socks5",
			})
			appendRec(row.RecordingPath, map[string]any{
				"t": time.Now().UTC().Format(time.RFC3339Nano),
				"event": "disconnect", "host": host, "port": port,
				"bytes_up": bytesUp, "bytes_down": bytesDown,
			})
			if pcapF != nil {
				_ = pcapF.Close()
				pcapF = nil
			}
		},
		tap,
	)
	if err != nil {
		slog.Debug("citrix socks", "err", err)
	}
	// Session lifecycle: MarkActive on CONNECT; end via portal/heartbeat (Workspace opens ICA+CGP).
}

func destAllowed(a assets.Asset, host string, port int) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	icaPort := a.Port
	if icaPort <= 0 {
		icaPort = 1494
	}
	if port != icaPort && port != 2598 {
		return false
	}
	for _, cand := range []string{a.Address, a.Hostname} {
		cand = strings.TrimSpace(strings.ToLower(cand))
		if cand == "" {
			continue
		}
		if host == cand {
			return true
		}
		// strip brackets / zone
		if strings.EqualFold(host, cand) {
			return true
		}
	}
	return false
}

func recordingPCAP(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".pcap"
	}
	return strings.TrimSuffix(path, ext) + ".pcap"
}

func appendRec(path string, row map[string]any) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(row)
}

func clientIP(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}
