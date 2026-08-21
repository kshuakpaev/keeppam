package telnet

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/keeppam/auth/internal/sshproxy"
)

// SessionOpts configures dial and optional vault login inject.
type SessionOpts struct {
	Username string
	Password string
	TermType string
	// InjectLogin waits briefly after negotiate then sends user/pass CR LF.
	InjectLogin bool
}

// Bridge is a bidirectional Telnet tty with asciicast recording (same shape as SSH Bridge for WS).
type Bridge struct {
	conn     net.Conn
	Recorder *sshproxy.Recorder

	mu       sync.Mutex
	cols     int
	rows     int
	closed   bool
	pending  []byte
	writeMu  sync.Mutex
	serverDo map[byte]bool // options we accepted DO for
}

// Dial opens TCP to host:port (default 23).
func Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if port <= 0 {
		port = 23
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

// StartBridge negotiates options and returns a live Bridge.
func StartBridge(conn net.Conn, cols, rows int, rec *sshproxy.Recorder, opts SessionOpts) (*Bridge, error) {
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 40
	}
	b := &Bridge{
		conn: conn, Recorder: rec, cols: cols, rows: rows,
		serverDo: map[byte]bool{},
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := b.negotiate(opts.TermType); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	if opts.InjectLogin && (opts.Username != "" || opts.Password != "") {
		time.Sleep(200 * time.Millisecond)
		if opts.Username != "" {
			_, _ = b.writeRaw([]byte(opts.Username + "\r\n"))
			time.Sleep(150 * time.Millisecond)
		}
		if opts.Password != "" {
			_, _ = b.writeRaw([]byte(opts.Password + "\r\n"))
		}
	}
	return b, nil
}

func (b *Bridge) negotiate(termType string) error {
	// Client: suppress local echo path via WILL ECHO refusal; enable SGA; offer NAWS/TTYPE.
	init := append([]byte{},
		cmdOpt(will, optSGA)...,
	)
	init = append(init, cmdOpt(do, optSGA)...)
	init = append(init, cmdOpt(wont, optEcho)...)
	init = append(init, cmdOpt(do, optEcho)...)
	init = append(init, cmdOpt(will, optNAWS)...)
	init = append(init, cmdOpt(will, optTType)...)
	if _, err := b.conn.Write(init); err != nil {
		return err
	}
	if _, err := b.conn.Write(nawsSub(b.cols, b.rows)); err != nil {
		return err
	}

	deadline := time.Now().Add(1500 * time.Millisecond)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		_ = b.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := b.conn.Read(buf)
		if n > 0 {
			app, rest := stripIAC(buf[:n], b.pending, b.onOpt, b.onSB(termType))
			b.pending = rest
			if len(app) > 0 && b.Recorder != nil {
				b.Recorder.WriteOutput(app)
			}
			// keep early banner bytes for later CopyOutput? discard into recorder only
			_ = app
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if err == io.EOF {
				break
			}
			// non-timeout during negotiate: still try to continue
			break
		}
	}
	_ = b.conn.SetReadDeadline(time.Time{})
	return nil
}

func (b *Bridge) onOpt(cmd, opt byte) {
	var resp []byte
	switch cmd {
	case will:
		switch opt {
		case optEcho, optSGA:
			resp = cmdOpt(do, opt)
		default:
			resp = cmdOpt(dont, opt)
		}
	case do:
		switch opt {
		case optSGA, optNAWS, optTType:
			resp = cmdOpt(will, opt)
			b.serverDo[opt] = true
			if opt == optNAWS {
				resp = append(resp, nawsSub(b.cols, b.rows)...)
			}
		case optEcho:
			resp = cmdOpt(wont, opt)
		default:
			resp = cmdOpt(wont, opt)
		}
	case wont, dont:
		// acknowledge silently
	}
	if len(resp) > 0 {
		_, _ = b.writeRaw(resp)
	}
}

func (b *Bridge) onSB(termType string) func(opt byte, data []byte) {
	return func(opt byte, data []byte) {
		if opt == optTType && len(data) > 0 && data[0] == 1 { // SEND
			_, _ = b.writeRaw(ttypeIs(termType))
		}
	}
}

func (b *Bridge) writeRaw(p []byte) (int, error) {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	return b.conn.Write(p)
}

// Write sends client keystrokes to the server (records as input).
func (b *Bridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	if b.Recorder != nil {
		b.Recorder.WriteInput(p)
	}
	return b.writeRaw(p)
}

// Resize sends NAWS subnegotiation.
func (b *Bridge) Resize(cols, rows int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return io.ErrClosedPipe
	}
	if cols > 0 {
		b.cols = cols
	}
	if rows > 0 {
		b.rows = rows
	}
	_, err := b.writeRaw(nawsSub(b.cols, b.rows))
	return err
}

// CopyOutput strips IAC and writes application data to dst (and recorder).
func (b *Bridge) CopyOutput(dst io.Writer) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := b.conn.Read(buf)
		if n > 0 {
			b.mu.Lock()
			app, rest := stripIAC(buf[:n], b.pending, b.onOpt, b.onSB(""))
			b.pending = rest
			b.mu.Unlock()
			if len(app) > 0 {
				if b.Recorder != nil {
					b.Recorder.WriteOutput(app)
				}
				if _, werr := dst.Write(app); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// Close ends the session and recorder.
func (b *Bridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	if b.conn != nil {
		_ = b.conn.Close()
	}
	if b.Recorder != nil {
		_ = b.Recorder.Close()
	}
}
