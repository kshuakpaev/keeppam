package sshgw

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/auth"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/device"
	"github.com/keeppam/auth/internal/firewall"
	"github.com/keeppam/auth/internal/itsm"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/opapprove"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/sshcmd"
	"github.com/keeppam/auth/internal/sshproxy"
	"github.com/keeppam/auth/internal/store"
)

type Gateway struct {
	addr        string
	hostKeyPath string
	auth        *auth.Service
	assets      *assets.Service
	policy      *policy.Service
	sessions    *sessionsvc.Service
	audit       *audit.Service
	live        *sessionsvc.LiveHub
	itsm        *itsm.Service
	ops         *opapprove.Service
	firewall    *firewall.Service
	conns       sync.Map // *ssh.ServerConn → *sshConnState

	targetsMu sync.RWMutex
	targets   []firewall.Target
	targetsAt time.Time
}

const maxEgressForwards = 8

type sshConnState struct {
	mu        sync.Mutex
	userID    uuid.UUID
	sessionID uuid.UUID
	snap      policy.Snapshot
	forwards  int32
}

func New(
	addr, hostKeyPath string,
	authSvc *auth.Service,
	assetsSvc *assets.Service,
	policySvc *policy.Service,
	sessSvc *sessionsvc.Service,
	auditSvc *audit.Service,
	live *sessionsvc.LiveHub,
	itsmSvc *itsm.Service,
	opsSvc *opapprove.Service,
	firewallSvc *firewall.Service,
) *Gateway {
	return &Gateway{
		addr: addr, hostKeyPath: hostKeyPath,
		auth: authSvc, assets: assetsSvc, policy: policySvc,
		sessions: sessSvc, audit: auditSvc, live: live, itsm: itsmSvc, ops: opsSvc,
		firewall: firewallSvc,
	}
}

func (g *Gateway) ListenAndServe() error {
	signer, err := loadOrCreateHostKey(g.hostKeyPath)
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-KeepPAM",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			u, err := g.auth.AuthenticatePassword(context.Background(), conn.User(), string(password), ip)
			crypto.Wipe(password)
			if err != nil {
				return nil, fmt.Errorf("access denied")
			}
			return sshPerms(u)
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			u, err := g.auth.AuthenticatePublicKey(context.Background(), conn.User(), key, ip)
			if err != nil {
				return nil, fmt.Errorf("access denied")
			}
			p, err := sshPerms(u)
			if err != nil {
				return nil, err
			}
			p.Extensions["auth_method"] = "publickey"
			p.Extensions["devices"] = strings.Join(device.FromSSHKey(key), ",")
			return p, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", g.addr)
	if err != nil {
		return err
	}
	slog.Info("ssh gateway listening", "addr", g.addr)

	for {
		tcp, err := ln.Accept()
		if err != nil {
			slog.Error("ssh accept", "err", err)
			continue
		}
		go g.handleConn(tcp, cfg)
	}
}

func (g *Gateway) handleConn(tcp net.Conn, cfg *ssh.ServerConfig) {
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(2 * time.Minute))
	sc, chans, reqs, err := ssh.NewServerConn(tcp, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	_ = tcp.SetDeadline(time.Time{})

	go g.handleGlobalReqs(sc, reqs)

	st := &sshConnState{}
	g.conns.Store(sc, st)
	defer g.conns.Delete(sc)

	for newCh := range chans {
		chType := newCh.ChannelType()
		if chType == "direct-tcpip" {
			go g.handleDirectTCPIP(sc, newCh)
			continue
		}
		if reason, deny := policy.SSHChannelDLP(chType); deny {
			_ = newCh.Reject(ssh.Prohibited, reason)
			g.auditSSHDLP(sc, reason, chType)
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go g.handleSession(sc, ch, requests)
	}
}

func (g *Gateway) handleGlobalReqs(sc *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if reason, deny := policy.SSHRequestDLP(req.Type); deny {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			g.auditSSHDLP(sc, reason, req.Type)
			continue
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func (g *Gateway) auditSSHDLP(sc *ssh.ServerConn, reason, detail string) {
	if sc.Permissions == nil {
		return
	}
	ext := sc.Permissions.Extensions
	uid, err := uuid.Parse(ext["user_id"])
	if err != nil {
		return
	}
	ip, _, _ := net.SplitHostPort(sc.RemoteAddr().String())
	_ = g.audit.Record(context.Background(), &uid, "session.dlp.denied", "session", "", ip, "ssh", map[string]any{
		"reason": reason, "detail": detail,
	})
}

func (g *Gateway) handleDirectTCPIP(sc *ssh.ServerConn, newCh ssh.NewChannel) {
	var msg struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil || strings.TrimSpace(msg.Host) == "" || msg.Port == 0 || msg.Port > 65535 {
		_ = newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip")
		return
	}
	host := strings.TrimSpace(msg.Host)
	port := int(msg.Port)

	v, ok := g.conns.Load(sc)
	if !ok {
		_ = newCh.Reject(ssh.Prohibited, "open a KeepPAM SSH session first")
		return
	}
	st := v.(*sshConnState)
	st.mu.Lock()
	snap := st.snap
	sessID := st.sessionID
	userID := st.userID
	st.mu.Unlock()
	if sessID == uuid.Nil {
		_ = newCh.Reject(ssh.Prohibited, "open a KeepPAM SSH session first")
		g.auditSSHDLP(sc, "ssh egress requires an active session", "direct-tcpip")
		return
	}

	if reason, deny := policy.AllowSSHEgress(snap, host, port); deny {
		_ = newCh.Reject(ssh.Prohibited, reason)
		g.auditEgress(sc, userID, sessID, "session.egress.denied", host, port, reason)
		_ = g.sessions.AddEvent(context.Background(), sessID, "egress_denied", map[string]any{
			"host": host, "port": port, "reason": reason,
		})
		return
	}

	if reason, deny := g.pamOnlyForwardBlocked(host, port, snap); deny {
		_ = newCh.Reject(ssh.Prohibited, reason)
		g.auditEgress(sc, userID, sessID, "session.egress.denied", host, port, reason)
		_ = g.sessions.AddEvent(context.Background(), sessID, "egress_denied", map[string]any{
			"host": host, "port": port, "reason": reason, "via": "firewall_pam",
		})
		return
	}

	n := atomic.AddInt32(&st.forwards, 1)
	if n > maxEgressForwards {
		atomic.AddInt32(&st.forwards, -1)
		_ = newCh.Reject(ssh.ResourceShortage, "too many forwards")
		return
	}
	defer atomic.AddInt32(&st.forwards, -1)

	dest := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "egress dial failed")
		g.auditEgress(sc, userID, sessID, "session.egress.denied", host, port, err.Error())
		_ = g.sessions.AddEvent(context.Background(), sessID, "egress_denied", map[string]any{
			"host": host, "port": port, "reason": "dial failed",
		})
		return
	}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok && policy.BlockedEgressIP(ta.IP) {
		_ = conn.Close()
		_ = newCh.Reject(ssh.Prohibited, "blocked destination")
		g.auditEgress(sc, userID, sessID, "session.egress.denied", host, port, "blocked destination")
		_ = g.sessions.AddEvent(context.Background(), sessID, "egress_denied", map[string]any{
			"host": host, "port": port, "reason": "blocked destination",
		})
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = conn.Close()
		return
	}
	defer ch.Close()
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	g.auditEgress(sc, userID, sessID, "session.egress.opened", host, port, "")
	_ = g.sessions.AddEvent(context.Background(), sessID, "egress", map[string]any{
		"host": host, "port": port,
	})

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, ch)
		_ = conn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ch, conn)
		_ = ch.Close()
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	_ = ch.Close()
	<-done
}

func (g *Gateway) pamOnlyForwardBlocked(host string, port int, snap policy.Snapshot) (string, bool) {
	if snap.BreakGlass || snap.AdminBypass || g.firewall == nil {
		return "", false
	}
	targets := g.loadFirewallTargets()
	return firewall.PamOnlyForwardBlocked(host, port, targets)
}

func (g *Gateway) loadFirewallTargets() []firewall.Target {
	g.targetsMu.RLock()
	if time.Since(g.targetsAt) < time.Minute && g.targets != nil {
		t := g.targets
		g.targetsMu.RUnlock()
		return t
	}
	g.targetsMu.RUnlock()

	g.targetsMu.Lock()
	defer g.targetsMu.Unlock()
	if time.Since(g.targetsAt) < time.Minute && g.targets != nil {
		return g.targets
	}
	list, err := g.firewall.ListTargets(context.Background())
	if err != nil {
		return g.targets
	}
	g.targets = list
	g.targetsAt = time.Now()
	return g.targets
}

func (g *Gateway) auditEgress(sc *ssh.ServerConn, userID, sessionID uuid.UUID, action, host string, port int, reason string) {
	ip, _, _ := net.SplitHostPort(sc.RemoteAddr().String())
	payload := map[string]any{"host": host, "port": port, "detail": "direct-tcpip"}
	if reason != "" {
		payload["reason"] = reason
	}
	_ = g.audit.Record(context.Background(), &userID, action, "session", sessionID.String(), ip, "ssh", payload)
}

type ptyInfo struct {
	Width  uint32
	Height uint32
}

func (g *Gateway) handleSession(sc *ssh.ServerConn, ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()

	ext := sc.Permissions.Extensions
	if ext["must_setup"] == "true" {
		_, _ = io.WriteString(ch, "KeepPAM: complete password change and MFA enrollment in the web UI first.\n")
		return
	}

	userID, err := uuid.Parse(ext["user_id"])
	if err != nil {
		_, _ = io.WriteString(ch, "internal auth error\n")
		return
	}
	roles := splitCSV(ext["roles"])
	perms := splitCSV(ext["perms"])
	ip, _, _ := net.SplitHostPort(sc.RemoteAddr().String())
	ctx := policy.WithDevices(context.Background(), device.Normalize(splitCSV(ext["devices"])))

	type sessStart struct {
		pty     ptyInfo
		execCmd string
	}
	startCh := make(chan sessStart, 1)
	resizeCh := make(chan ptyInfo, 8)
	var startOnce sync.Once
	var agentWanted atomic.Bool

	go func() {
		var pty ptyInfo
		for req := range requests {
			switch req.Type {
			case "pty-req":
				p, ok := parsePtyReq(req.Payload)
				if !ok {
					_ = req.Reply(false, nil)
					continue
				}
				pty = p
				_ = req.Reply(true, nil)
			case "shell":
				_ = req.Reply(true, nil)
				startOnce.Do(func() { startCh <- sessStart{pty: pty} })
			case "exec":
				cmd, _ := parseExec(req.Payload)
				if kind, ok := policy.FileTransferCommand(cmd); ok {
					_ = req.Reply(false, nil)
					g.auditSSHDLP(sc, "ssh file transfer denied by DLP", kind+": "+cmd)
					continue
				}
				_ = req.Reply(true, nil)
				startOnce.Do(func() { startCh <- sessStart{pty: pty, execCmd: cmd} })
			case "subsystem":
				name, _ := parseExec(req.Payload)
				if reason, deny := policy.SSHSubsystemDLP(name); deny {
					_ = req.Reply(false, nil)
					g.auditSSHDLP(sc, reason, "subsystem:"+name)
					continue
				}
				_ = req.Reply(false, nil)
			case "x11-req":
				reason, _ := policy.SSHRequestDLP("x11-req")
				_ = req.Reply(false, nil)
				g.auditSSHDLP(sc, reason, "x11-req")
			case "window-change":
				w, h, ok := parseWinChange(req.Payload)
				if ok {
					select {
					case resizeCh <- ptyInfo{Width: w, Height: h}:
					default:
					}
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "auth-agent-req@openssh.com":
				agentWanted.Store(true)
				_ = req.Reply(true, nil)
			case "env", "signal", "keepalive@openssh.com":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	var start sessStart
	select {
	case start = <-startCh:
	case <-time.After(30 * time.Second):
		_, _ = io.WriteString(ch, "timeout waiting for shell\n")
		return
	}

	if ext["mfa"] == "true" {
		_, _ = io.WriteString(ch, "TOTP: ")
		code, err := readLine(ch)
		if err != nil {
			return
		}
		if err := g.auth.ValidateTOTP(ctx, userID, strings.TrimSpace(code), ip); err != nil {
			_, _ = io.WriteString(ch, "invalid MFA code\r\n")
			return
		}
	} else {
		_ = g.audit.Record(ctx, &userID, "user.login.success", "user", userID.String(), ip, "ssh", map[string]any{"mfa": false, "via": "ssh"})
	}

	targets, err := g.listTargets(ctx, userID, roles, perms)
	if err != nil {
		_, _ = fmt.Fprintf(ch, "error listing targets: %v\n", err)
		return
	}
	if len(targets) == 0 {
		_, _ = io.WriteString(ch, "No SSH targets available (check ACL policy).\n")
		_ = g.audit.Record(ctx, &userID, "session.denied", "session", "", ip, "ssh", map[string]any{"reason": "no_targets"})
		return
	}

	var chosen *targetRef
	var ticketID string
	cmd := strings.TrimSpace(start.execCmd)
	if cmd != "" {
		cmd, ticketID = splitTicket(cmd)
		chosen, err = resolveTarget(targets, cmd)
		if err != nil {
			_, _ = fmt.Fprintf(ch, "%v\n", err)
			return
		}
	} else {
		chosen, err = interactivePick(ch, targets)
		if err != nil {
			_, _ = fmt.Fprintf(ch, "%v\n", err)
			return
		}
		_, _ = io.WriteString(ch, "Ticket ID (optional): ")
		if line, err := readLine(ch); err == nil {
			ticketID = strings.TrimSpace(line)
		}
	}

	bypassConnect := rbac.HasPermission(perms, "users.write")
	usedBreakGlass := false
	evPolicy, err := g.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: chosen.AssetID, RoleNames: roles, Bypass: false, Now: time.Now(), TicketID: ticketID, ClientIP: ip,
	})
	if err != nil {
		_, _ = fmt.Fprintf(ch, "policy error: %v\n", err)
		return
	}
	okPolicy := evPolicy.OK
	if !okPolicy {
		if bg, berr := g.policy.HasActiveBreakGlass(ctx, userID, chosen.AssetID); berr == nil && bg {
			okPolicy = true
			usedBreakGlass = true
		}
	}
	if !okPolicy && bypassConnect {
		_ = g.audit.Record(ctx, &userID, "session.admin_bypass", "asset", chosen.AssetID.String(), ip, "ssh", map[string]any{"severity": "high", "ticket_id": ticketID})
		okPolicy = true
	}
	if !okPolicy && evPolicy.NeedsStepUp() {
		methods, _ := g.auth.MFAMethods(ctx, userID)
		if !methods.TOTP {
			_, _ = fmt.Fprintf(ch, "step-up MFA required (score %d > %d) but TOTP is not enrolled\r\n", evPolicy.RiskScore, evPolicy.MaxRisk)
			payload := map[string]any{"reason": "risk", "ticket_id": ticketID, "code": "mfa_not_enrolled"}
			evPolicy.FillDenyPayload(payload)
			_ = g.audit.Record(ctx, &userID, "session.denied", "asset", chosen.AssetID.String(), ip, "ssh", payload)
			return
		}
		_, _ = fmt.Fprintf(ch, "Step-up MFA (risk %d > %d). TOTP: ", evPolicy.RiskScore, evPolicy.MaxRisk)
		code, rerr := readLine(ch)
		if rerr != nil {
			return
		}
		if err := g.auth.VerifyUserTOTP(ctx, userID, strings.TrimSpace(code), ip, "ssh", "ssh", chosen.AssetID); err != nil {
			_, _ = io.WriteString(ch, "invalid MFA code\r\n")
			payload := map[string]any{"reason": "risk", "ticket_id": ticketID}
			evPolicy.FillDenyPayload(payload)
			_ = g.audit.Record(ctx, &userID, "session.denied", "asset", chosen.AssetID.String(), ip, "ssh", payload)
			return
		}
		okPolicy = true
	}
	if !okPolicy {
		_, _ = fmt.Fprintf(ch, "%s\r\n", evPolicy.DenyMessage())
		payload := map[string]any{"reason": "policy", "ticket_id": ticketID}
		evPolicy.FillDenyPayload(payload)
		_ = g.audit.Record(ctx, &userID, "session.denied", "asset", chosen.AssetID.String(), ip, "ssh", payload)
		return
	}
	if g.itsm != nil && !usedBreakGlass && !bypassConnect {
		if err := g.itsm.Enforce(ctx, "connect", ticketID); err != nil {
			_, _ = fmt.Fprintf(ch, "ITSM gate: %v\r\n", err)
			_ = g.audit.Record(ctx, &userID, "session.denied", "asset", chosen.AssetID.String(), ip, "ssh", map[string]any{
				"reason": "itsm", "ticket_id": ticketID, "error": err.Error(),
			})
			return
		}
	}

	cols, rows := 120, 40
	if start.pty.Width > 0 {
		cols = int(start.pty.Width)
	}
	if start.pty.Height > 0 {
		rows = int(start.pty.Height)
	}

	creds, err := g.assets.GetTargetCreds(ctx, chosen.AssetID, chosen.AccountID)
	if err != nil {
		_, _ = fmt.Fprintf(ch, "target credentials: %v\n", err)
		return
	}

	labels := sessionsvc.MergeLabels()
	if ut, err := g.policy.UserTags(ctx, userID); err == nil {
		labels = sessionsvc.MergeLabels(labels, ut)
	}
	if at, err := g.policy.AssetTags(ctx, chosen.AssetID); err == nil {
		labels = sessionsvc.MergeLabels(labels, at)
	}
	frozen := g.policy.Freeze(ctx, evPolicy, usedBreakGlass, bypassConnect)
	snap := &frozen
	pamSess, err := g.sessions.Create(ctx, userID, sessionsvc.CreateInput{
		AssetID: chosen.AssetID, AccountID: chosen.AccountID, Protocol: "ssh", ClientIP: ip, TicketID: ticketID,
		BreakGlass: usedBreakGlass, RiskScore: evPolicy.RiskScore, RiskFactors: evPolicy.RiskFactors,
		Labels: labels, AccessPolicyID: evPolicy.AccessPolicyID, ClientCountry: g.policy.ClientCountry(ip),
		PolicySnapshot: snap,
	}, "ssh-gateway")
	if err != nil {
		_, _ = fmt.Fprintf(ch, "session create: %v\n", err)
		return
	}
	if v, ok := g.conns.Load(sc); ok {
		st := v.(*sshConnState)
		st.mu.Lock()
		st.userID = userID
		st.sessionID = pamSess.ID
		st.snap = frozen
		st.mu.Unlock()
		defer func() {
			st.mu.Lock()
			if st.sessionID == pamSess.ID {
				st.sessionID = uuid.Nil
			}
			st.mu.Unlock()
		}()
	}

	rec, err := sshproxy.NewRecorder(pamSess.RecordingPath, cols, rows, chosen.Label)
	if err != nil {
		_ = g.sessions.MarkEnded(ctx, pamSess.ID, err.Error())
		_, _ = fmt.Fprintf(ch, "recorder: %v\n", err)
		return
	}

	client, err := g.assets.DialSSH(ctx, creds)
	creds.WipeSecret()
	if err != nil {
		_ = rec.Close()
		_ = g.sessions.MarkEnded(ctx, pamSess.ID, err.Error())
		_ = g.audit.Record(ctx, &userID, "session.failed", "session", pamSess.ID.String(), ip, "ssh", map[string]any{"error": err.Error()})
		_, _ = fmt.Fprintf(ch, "connect failed: %v\n", err)
		return
	}

	var agentUpstream ssh.Conn
	if agentWanted.Load() {
		agentUpstream = sc
	}
	var injectMu sync.Mutex
	opts := sshcmd.Deps{Policy: g.policy, Ops: g.ops, Sessions: g.sessions, Audit: g.audit}.BuildOpts(ctx, sshcmd.Meta{
		UserID: userID, AssetID: chosen.AssetID, SessionID: pamSess.ID,
		Username: ext["username"], AssetName: chosen.AssetName, IP: ip,
		Roles: roles, Bypass: bypassConnect, BreakGlass: usedBreakGlass,
		TicketID: ticketID, Snap: snap,
		Inject: func(p []byte) {
			injectMu.Lock()
			defer injectMu.Unlock()
			_, _ = ch.Write(p)
		},
	})
	opts.AgentUpstream = agentUpstream
	bridge, err := sshproxy.StartSessionWith(client, cols, rows, rec, opts)
	if err != nil {
		_ = client.Close()
		_ = rec.Close()
		_ = g.sessions.MarkEnded(ctx, pamSess.ID, err.Error())
		_, _ = fmt.Fprintf(ch, "session start failed: %v\n", err)
		return
	}
	defer bridge.Close()

	_ = g.sessions.MarkActive(ctx, pamSess.ID)
	ctx, endSpan := obs.StartSessionSpan(ctx, "ssh", pamSess.ID.String(), chosen.AssetName)
	defer endSpan()
	_ = g.audit.Record(ctx, &userID, "session.started", "session", pamSess.ID.String(), ip, "ssh", map[string]any{
		"asset": chosen.AssetName, "account": chosen.AccountName, "via": "sshgw",
	})
	_, _ = fmt.Fprintf(ch, "Connected to %s as %s (session %s)\r\n", chosen.AssetName, chosen.AccountName, pamSess.ID.String()[:8])

	unregister := g.live.Register(pamSess.ID, func() {
		bridge.Close()
		_ = ch.Close()
	})
	defer unregister()

	hbStop := make(chan struct{})
	go sessionsvc.Heartbeat(ctx, g.sessions, pamSess.ID, 30*time.Second, hbStop)
	defer close(hbStop)

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_ = bridge.CopyOutput(liveCopy{live: g.live, id: pamSess.ID, dst: ch, ctx: ctx})
	}()

	go func() {
		for {
			select {
			case r, ok := <-resizeCh:
				if !ok {
					return
				}
				_ = bridge.Resize(int(r.Width), int(r.Height))
			case <-outDone:
				return
			}
		}
	}()

	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				if _, werr := bridge.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-outDone:
	case <-inDone:
	}
	bridge.Close()
	_ = ch.Close()
	select {
	case <-outDone:
	case <-time.After(2 * time.Second):
	}
	select {
	case <-inDone:
	case <-time.After(500 * time.Millisecond):
	}

	_ = g.sessions.MarkEnded(ctx, pamSess.ID, "")
	_ = g.audit.Record(ctx, &userID, "session.ended", "session", pamSess.ID.String(), ip, "ssh", map[string]any{"via": "sshgw"})
}

type targetRef struct {
	AssetID     uuid.UUID
	AccountID   uuid.UUID
	AssetName   string
	AccountName string
	Address     string
	Port        int
	Label       string
}

func (g *Gateway) listTargets(ctx context.Context, userID uuid.UUID, roles, perms []string) ([]targetRef, error) {
	bypass := rbac.HasPermission(perms, "users.write")
	list, err := g.assets.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []targetRef
	now := time.Now()
	for _, a := range list {
		if a.Protocol != "ssh" || a.Status != "active" {
			continue
		}
		ok, err := g.policy.Allowed(ctx, policy.AccessCheck{
			UserID: userID, AssetID: a.ID, RoleNames: roles, Bypass: bypass, Now: now, IgnoreTicket: true, SkipRisk: true,
		})
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		full, err := g.assets.Get(ctx, a.ID)
		if err != nil {
			continue
		}
		for _, acc := range full.Accounts {
			if acc.Status != "active" || !acc.HasSecret {
				continue
			}
			out = append(out, targetRef{
				AssetID: a.ID, AccountID: acc.ID,
				AssetName: a.Name, AccountName: acc.Username,
				Address: a.Address, Port: a.Port,
				Label: fmt.Sprintf("%s/%s", a.Name, acc.Username),
			})
		}
	}
	return out, nil
}

func splitTicket(cmd string) (target, ticket string) {
	cmd = strings.TrimSpace(cmd)
	if i := strings.LastIndex(cmd, "#"); i >= 0 {
		return strings.TrimSpace(cmd[:i]), strings.TrimSpace(cmd[i+1:])
	}
	return cmd, ""
}

func resolveTarget(targets []targetRef, cmd string) (*targetRef, error) {
	cmd = strings.TrimSpace(cmd)
	if n, err := strconv.Atoi(cmd); err == nil {
		if n < 1 || n > len(targets) {
			return nil, fmt.Errorf("invalid selection")
		}
		t := targets[n-1]
		return &t, nil
	}
	assetName := cmd
	accountName := ""
	if i := strings.IndexByte(cmd, '/'); i >= 0 {
		assetName = cmd[:i]
		accountName = cmd[i+1:]
	}
	var matches []targetRef
	for _, t := range targets {
		if !strings.EqualFold(t.AssetName, assetName) {
			continue
		}
		if accountName == "" || strings.EqualFold(t.AccountName, accountName) {
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("target not found or denied: %s", cmd)
	}
	if len(matches) > 1 && accountName == "" {
		return nil, fmt.Errorf("ambiguous asset %s — use asset/account", assetName)
	}
	return &matches[0], nil
}

func interactivePick(ch ssh.Channel, targets []targetRef) (*targetRef, error) {
	_, _ = io.WriteString(ch, "\r\nKeepPAM — select target:\r\n")
	for i, t := range targets {
		_, _ = fmt.Fprintf(ch, "  %d) %s  (%s:%d)\r\n", i+1, t.Label, t.Address, t.Port)
	}
	_, _ = io.WriteString(ch, "Enter number or asset/account: ")
	line, err := readLine(ch)
	if err != nil {
		return nil, err
	}
	return resolveTarget(targets, strings.TrimSpace(line))
}

// readLine reads a line from an SSH session channel. With a PTY, OpenSSH sends
// CR on Enter (not LF), and the client expects the server to echo keystrokes.
func readLine(ch ssh.Channel) (string, error) {
	br := bufio.NewReader(ch)
	var b strings.Builder
	for {
		c, err := br.ReadByte()
		if err != nil {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
		switch c {
		case '\n':
			_, _ = io.WriteString(ch, "\r\n")
			return b.String(), nil
		case '\r':
			if next, err := br.Peek(1); err == nil && next[0] == '\n' {
				_, _ = br.ReadByte()
			}
			_, _ = io.WriteString(ch, "\r\n")
			return b.String(), nil
		case 127, 8: // backspace / DEL
			s := b.String()
			if len(s) > 0 {
				b.Reset()
				b.WriteString(s[:len(s)-1])
				_, _ = ch.Write([]byte{8, ' ', 8})
			}
		case 3: // Ctrl-C
			return "", io.EOF
		case 4: // Ctrl-D
			if b.Len() == 0 {
				return "", io.EOF
			}
			_, _ = io.WriteString(ch, "\r\n")
			return b.String(), nil
		default:
			if c >= 32 && c < 127 {
				b.WriteByte(c)
				_, _ = ch.Write([]byte{c})
			}
		}
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sshPerms(u store.User) (*ssh.Permissions, error) {
	if !rbac.HasPermission(u.Permissions, "sessions.connect") {
		return nil, fmt.Errorf("access denied")
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":     u.ID.String(),
			"username":    u.Username,
			"mfa":         strconv.FormatBool(u.MFAEnabled),
			"roles":       strings.Join(u.Roles, ","),
			"perms":       strings.Join(u.Permissions, ","),
			"must_setup":  strconv.FormatBool(u.MustChangePassword || !u.MFAEnabled),
			"auth_method": "password",
		},
	}, nil
}

func parsePtyReq(b []byte) (ptyInfo, bool) {
	_, rest, ok := parseString(b)
	if !ok || len(rest) < 8 {
		return ptyInfo{}, false
	}
	w := be32(rest[0:4])
	h := be32(rest[4:8])
	return ptyInfo{Width: w, Height: h}, true
}

func parseWinChange(b []byte) (w, h uint32, ok bool) {
	if len(b) < 8 {
		return 0, 0, false
	}
	return be32(b[0:4]), be32(b[4:8]), true
}

func parseExec(b []byte) (string, bool) {
	s, _, ok := parseString(b)
	return s, ok
}

func parseString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := int(be32(b[0:4]))
	if n < 0 || len(b) < 4+n {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		path = "/tmp/keeppam-ssh-hostkey"
	}
	if data, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(data)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}

type liveCopy struct {
	live *sessionsvc.LiveHub
	id   uuid.UUID
	dst  io.Writer
	ctx  context.Context
}

func (w liveCopy) Write(p []byte) (int, error) {
	if w.live != nil && len(p) > 0 {
		w.live.FanoutOutput(w.ctx, w.id, p)
	}
	return w.dst.Write(p)
}
