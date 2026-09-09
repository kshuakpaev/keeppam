package rdpgw

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/wwt/guac"

	"github.com/keeppam/auth/internal/guacd"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (b *Broker) startVNCRecorder(sessionID uuid.UUID, vncHost string, vncPort, width, height int) (func(), error) {
	addrs := guacd.Parse(b.Jump.GuacdAddr)
	conn, err := guacd.Dial(addrs, 15*time.Second)
	if err != nil {
		return nil, err
	}
	stream := guac.NewStream(conn, guac.SocketTimeout)
	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = "vnc"
	cfg.OptimalScreenWidth = width
	cfg.OptimalScreenHeight = height
	cfg.Parameters = map[string]string{
		"hostname":      vncHost,
		"port":          strconv.Itoa(vncPort),
		"width":         strconv.Itoa(width),
		"height":        strconv.Itoa(height),
		"dpi":           "96",
		"color-depth":   "24",
		"disable-copy":  "true",
		"disable-paste": "true",
	}
	recDir := b.recordingsDir()
	if recDir != "" {
		cfg.Parameters["recording-path"] = filepath.Join(recDir, "guac")
		cfg.Parameters["create-recording-path"] = "true"
		cfg.Parameters["recording-name"] = sessionID.String()
		cfg.Parameters["recording-include-keys"] = "true"
	}
	if err := stream.Handshake(cfg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("guacd vnc handshake: %w", err)
	}
	tunnel := guac.NewSimpleTunnel(stream)
	done := make(chan struct{})
	if b.sessions != nil {
		go sessionsvc.Heartbeat(context.Background(), b.sessions, sessionID, 30*time.Second, done)
	}
	go func() {
		defer close(done)
		defer tunnel.Close()
		reader := tunnel.AcquireReader()
		defer tunnel.ReleaseReader()
		for {
			if _, err := reader.ReadSome(); err != nil {
				slog.Info("rdp jump recorder ended", "session", sessionID.String(), "err", err)
				return
			}
		}
	}()
	stop := func() {
		_ = tunnel.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	return stop, nil
}
