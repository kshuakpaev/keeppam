package httpapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/wwt/guac"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/guacd"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/rdpgw"
	"github.com/keeppam/auth/internal/sessionsvc"
)

var guacUpgrader = websocket.Upgrader{
	ReadBufferSize:  guac.MaxGuacMessage,
	WriteBufferSize: guac.MaxGuacMessage * 2,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	Subprotocols: []string{"guacamole"},
}

// handleSessionGuac tunnels browser Guacamole WebSocket ↔ guacd for RDP/VNC.
func (s *Server) handleSessionGuac(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	authSess, err := s.sessions.Get(r.Context(), c.Value)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.touchOrExpire(r, c.Value, &authSess); err != nil {
		s.clearCookies(w)
		http.Error(w, "idle timeout", http.StatusUnauthorized)
		return
	}
	r = s.bindSession(r, authSess)
	if !rbac.HasPermission(authSess.Permissions, "sessions.connect") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if row.UserID != authSess.UserID && !rbac.HasPermission(authSess.Permissions, "sessions.read") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	isolated := row.Isolated || (row.Protocol == "https" && s.apps != nil && s.apps.IsIsolated(r.Context(), row.AssetID))
	if row.Protocol != "rdp" && row.Protocol != "vnc" && !isolated {
		http.Error(w, "not a graphical session", http.StatusBadRequest)
		return
	}
	if row.IsWaitingSupervisor() {
		http.Error(w, "waiting for supervisor", http.StatusConflict)
		return
	}

	creds, err := s.assets.GetTargetCreds(r.Context(), row.AssetID, row.AccountID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	width, _ := strconv.Atoi(r.URL.Query().Get("width"))
	height, _ := strconv.Atoi(r.URL.Query().Get("height"))
	if row.RDPWidth > 0 && row.RDPHeight > 0 {
		width = row.RDPWidth
		height = row.RDPHeight
	} else {
		width, height = rdpgw.NormalizeSize(width, height)
	}

	guacProto := row.Protocol
	host := creds.Asset.Address
	port := creds.Asset.Port
	user := creds.Account.Username
	pass := creds.Secret
	if isolated {
		loginURL := ""
		if integ, err := s.apps.GetIntegration(r.Context(), row.AssetID); err == nil {
			loginURL = integ.LoginURL
		}
		ep, err := s.apps.IsolateStart(r.Context(), id, creds, loginURL)
		if err != nil {
			slog.Error("iso browser", "err", err, "session", id.String())
			_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		guacProto = "vnc"
		host = ep.Host
		port = ep.Port
		user = ""
		pass = ""
	}

	tunnel, err := s.openGuacTunnel(guacProto, host, port, user, pass, width, height, id, row.PolicySnapshot, creds.Asset)
	if err != nil {
		slog.Error("guac tunnel", "err", err, "session", id.String())
		_ = s.sessionsvc.MarkEnded(r.Context(), id, err.Error())
		_ = s.audit.Record(r.Context(), &authSess.UserID, "session.failed", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"error": err.Error()})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer tunnel.Close()

	hdr := http.Header{}
	if p := r.Header.Get("Sec-Websocket-Protocol"); p != "" {
		hdr.Set("Sec-Websocket-Protocol", p)
	} else {
		hdr.Set("Sec-Websocket-Protocol", "guacamole")
	}
	ws, err := guacUpgrader.Upgrade(w, r, hdr)
	if err != nil {
		return
	}
	defer ws.Close()

	// Guacamole WebSocket tunnel requires an internal UUID instruction first.
	uuidIns := guac.NewInstruction(guac.InternalDataOpcode, tunnel.GetUUID())
	if err := ws.WriteMessage(websocket.TextMessage, uuidIns.Byte()); err != nil {
		return
	}

	_ = s.sessionsvc.MarkActive(r.Context(), id)
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.started", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{
		"asset": creds.Asset.Name, "account": creds.Account.Username, "protocol": row.Protocol, "via": "guac",
		"remote_app": creds.Asset.RDPRemoteApp,
	})

	unregister := s.live.Register(id, func() {
		_ = tunnel.Close()
		_ = ws.Close()
	})
	defer unregister()

	hbStop := make(chan struct{})
	go sessionsvc.Heartbeat(r.Context(), s.sessionsvc, id, 30*time.Second, hbStop)
	defer close(hbStop)

	writer := tunnel.AcquireWriter()
	reader := tunnel.AcquireReader()
	defer tunnel.ReleaseWriter()
	defer tunnel.ReleaseReader()

	var wsWriteMu sync.Mutex
	ioDone := make(chan struct{})
	go func() {
		defer close(ioDone)
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				_ = tunnel.Close()
				return
			}
			// Internal opcode messages are never forwarded to guacd.
			if bytes.HasPrefix(data, []byte("0.")) {
				continue
			}
			if _, err := writer.Write(data); err != nil {
				return
			}
		}
	}()

	buf := bytes.NewBuffer(make([]byte, 0, guac.MaxGuacMessage*2))
	for {
		ins, err := reader.ReadSome()
		if err != nil {
			break
		}
		if bytes.HasPrefix(ins, []byte("0.")) {
			continue
		}
		_, _ = buf.Write(ins)
		if !reader.Available() || buf.Len() >= guac.MaxGuacMessage {
			wsWriteMu.Lock()
			werr := ws.WriteMessage(websocket.TextMessage, append([]byte(nil), buf.Bytes()...))
			wsWriteMu.Unlock()
			if werr != nil {
				break
			}
			buf.Reset()
		}
	}
	<-ioDone

	_ = s.sessionsvc.MarkEnded(r.Context(), id, "")
	_ = s.audit.Record(r.Context(), &authSess.UserID, "session.ended", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"via": "guac"})
}

func (s *Server) openGuacTunnel(protocol, address string, port int, username, password string, width, height int, sessID uuid.UUID, snap *policy.Snapshot, asset assets.Asset) (guac.Tunnel, error) {
	addrs := guacd.Parse(s.cfg.GuacdAddr)
	conn, err := guacd.Dial(addrs, 15*time.Second)
	if err != nil {
		return nil, err
	}
	stream := guac.NewStream(conn, guac.SocketTimeout)
	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = protocol
	cfg.OptimalScreenWidth = width
	cfg.OptimalScreenHeight = height
	cfg.AudioMimetypes = []string{"audio/L16", "rate=44100", "channels=2"}
	cfg.Parameters = map[string]string{
		"hostname":    address,
		"port":        strconv.Itoa(port),
		"username":    username,
		"password":    password,
		"width":       strconv.Itoa(width),
		"height":      strconv.Itoa(height),
		"dpi":         "96",
		"color-depth": "24",
	}
	rdp := policy.RDPRedir{}
	ft := policy.FileTransferDeny
	if snap != nil {
		rdp = snap.RDP()
		ft = snap.EffectiveFileTransfer()
	}
	switch protocol {
	case "rdp":
		cfg.Parameters["security"] = "any"
		cfg.Parameters["ignore-cert"] = "true"
		cfg.Parameters["resize-method"] = "display-update"
		cfg.Parameters["enable-wallpaper"] = "false"
		cfg.Parameters["enable-font-smoothing"] = "true"
		cfg.Parameters["disable-audio"] = "true"
		if rdp.Clipboard {
			cfg.Parameters["disable-copy"] = "false"
			cfg.Parameters["disable-paste"] = "false"
		} else {
			cfg.Parameters["disable-copy"] = "true"
			cfg.Parameters["disable-paste"] = "true"
		}
		captureFiles := !policy.FileTransferDenied(ft)
		if rdp.Drive {
			driveDir := filepath.Join(s.cfg.RecordingsDir, "rdp-drive", sessID.String())
			cfg.Parameters["enable-drive"] = "true"
			cfg.Parameters["drive-path"] = driveDir
			cfg.Parameters["create-drive-path"] = "true"
		} else if rdp.Clipboard && captureFiles {
			// Clipboard file drops land in a staging drive (guacd cliprdr → redirected folder).
			clipDir := filepath.Join(s.cfg.RecordingsDir, "rdp-clipboard", sessID.String())
			cfg.Parameters["enable-drive"] = "true"
			cfg.Parameters["drive-name"] = "KeepPAMClip"
			cfg.Parameters["drive-path"] = clipDir
			cfg.Parameters["create-drive-path"] = "true"
		} else {
			cfg.Parameters["enable-drive"] = "false"
		}
		if rdp.Printer {
			cfg.Parameters["enable-printing"] = "true"
		} else {
			cfg.Parameters["enable-printing"] = "false"
		}
		if app := strings.TrimSpace(asset.RDPRemoteApp); app != "" {
			cfg.Parameters["remote-app"] = app
			if d := strings.TrimSpace(asset.RDPRemoteAppDir); d != "" {
				cfg.Parameters["remote-app-dir"] = d
			}
			if a := strings.TrimSpace(asset.RDPRemoteAppArgs); a != "" {
				cfg.Parameters["remote-app-args"] = a
			}
		}
	case "vnc":
		if rdp.Clipboard {
			cfg.Parameters["disable-copy"] = "false"
			cfg.Parameters["disable-paste"] = "false"
		} else {
			cfg.Parameters["disable-copy"] = "true"
			cfg.Parameters["disable-paste"] = "true"
		}
	}
	if s.cfg.RecordingsDir != "" {
		recDir := filepath.Join(s.cfg.RecordingsDir, "guac")
		cfg.Parameters["recording-path"] = recDir
		cfg.Parameters["create-recording-path"] = "true"
		cfg.Parameters["recording-name"] = sessID.String()
		cfg.Parameters["recording-include-keys"] = "true"
	}
	if err := stream.Handshake(cfg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("guacd handshake: %w", err)
	}
	return guac.NewSimpleTunnel(stream), nil
}
