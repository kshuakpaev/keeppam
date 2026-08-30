package sshproxy

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/sshlegacy"
	"github.com/keeppam/auth/internal/termcharset"
)

// Recorder writes asciicast v2 (newline-delimited JSON).
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	start   time.Time
	Charset string // utf-8|cp1251|koi8-r|auto — decode before JSON (valid UTF-8)
}

func NewRecorder(path string, cols, rows int, title string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir recordings: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open recording: %w", err)
	}
	header := map[string]any{
		"version":   2,
		"width":     cols,
		"height":    rows,
		"timestamp": time.Now().Unix(),
		"title":     title,
		"env":       map[string]string{"TERM": "xterm-256color"},
	}
	b, _ := json.Marshal(header)
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Recorder{f: f, start: time.Now()}, nil
}

func (r *Recorder) SetCharset(cs string) {
	if r == nil {
		return
	}
	r.Charset = termcharset.Normalize(cs)
}

func (r *Recorder) WriteOutput(data []byte) {
	r.writeEvent("o", data)
}

func (r *Recorder) WriteInput(data []byte) {
	r.writeEvent("i", data)
}

func (r *Recorder) writeEvent(kind string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return
	}
	text := termcharset.Decode(data, r.Charset).Text
	sec := time.Since(r.start).Seconds()
	b, _ := json.Marshal([]any{sec, kind, text})
	_, _ = r.f.Write(append(b, '\n'))
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

type DialConfig struct {
	Address    string
	Port       int
	Username   string
	AuthMethod string // password | ssh_key | ssh_cert | gssapi
	Secret     string
	// Signer is used when AuthMethod=ssh_cert (ephemeral CA-signed key).
	Signer ssh.Signer
	// GSSAPI client + target hostname (x/crypto builds SPN host/<target>).
	GSSAPI       ssh.GSSAPIClient
	GSSAPITarget string
	// HostKey is the previously learned marshaled public key (TOFU). Empty = learn on first connect.
	HostKey []byte
	// OnHostKey is called when HostKey is empty and the remote presents a key (first-seen trust).
	OnHostKey func(algo string, key ssh.PublicKey) error
}

func Dial(cfg DialConfig) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	switch cfg.AuthMethod {
	case "gssapi":
		if cfg.GSSAPI == nil {
			return nil, fmt.Errorf("gssapi requires client")
		}
		target := cfg.GSSAPITarget
		if target == "" {
			target = cfg.Address
		}
		auth = append(auth, ssh.GSSAPIWithMICAuthMethod(cfg.GSSAPI, target))
	case "ssh_cert":
		if cfg.Signer == nil {
			return nil, fmt.Errorf("ssh_cert requires signer")
		}
		auth = append(auth, ssh.PublicKeys(cfg.Signer))
	case "ssh_key":
		signer, err := ssh.ParsePrivateKey([]byte(cfg.Secret))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	default:
		auth = append(auth, ssh.Password(cfg.Secret))
		auth = append(auth, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = cfg.Secret
			}
			return answers, nil
		}))
	}
	sshCfg := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			got := key.Marshal()
			if len(cfg.HostKey) > 0 {
				if subtle.ConstantTimeCompare(got, cfg.HostKey) != 1 {
					return fmt.Errorf("host key mismatch for %s (got %s)", hostname, ssh.FingerprintSHA256(key))
				}
				return nil
			}
			if cfg.OnHostKey == nil {
				return fmt.Errorf("host key unknown for %s and TOFU disabled", hostname)
			}
			return cfg.OnHostKey(key.Type(), key)
		},
		Timeout: 15 * time.Second,
	}
	if sshlegacy.Enabled() {
		sshlegacy.ApplyClient(sshCfg)
	}
	// Pin host-key algorithms to the TOFU key so a later ClientConfig change
	// cannot make OpenSSH present a different key type (RSA vs ECDSA).
	if algos := hostKeyAlgorithmsFor(cfg.HostKey); len(algos) > 0 {
		sshCfg.HostKeyAlgorithms = algos
	}
	addr := net.JoinHostPort(cfg.Address, fmt.Sprintf("%d", cfg.Port))
	return ssh.Dial("tcp", addr, sshCfg)
}

func hostKeyAlgorithmsFor(blob []byte) []string {
	if len(blob) == 0 {
		return nil
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519:
		return []string{ssh.KeyAlgoED25519}
	case ssh.KeyAlgoECDSA256:
		return []string{ssh.KeyAlgoECDSA256}
	case ssh.KeyAlgoECDSA384:
		return []string{ssh.KeyAlgoECDSA384}
	case ssh.KeyAlgoECDSA521:
		return []string{ssh.KeyAlgoECDSA521}
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	case ssh.InsecureKeyAlgoDSA:
		return []string{ssh.InsecureKeyAlgoDSA}
	default:
		return []string{pk.Type()}
	}
}

// Bridge copies between a remote SSH session and local reader/writer, recording I/O.
type Bridge struct {
	Client      *ssh.Client
	Session     *ssh.Session
	Recorder    *Recorder
	stdinPipe   io.WriteCloser
	stdout      io.Reader
	stderr      io.Reader
	Guard       *CommandGuard
	LocalInject func([]byte)
	OnDenied    func(line string)
}

type SessionOpts struct {
	AgentUpstream ssh.Conn
	Guard         *CommandGuard
	LocalInject   func([]byte)
	OnDenied      func(line string)
	// QuietEcho disables remote ECHO (for JEA local line buffering).
	QuietEcho bool
}

func StartSession(client *ssh.Client, cols, rows int, rec *Recorder) (*Bridge, error) {
	return StartSessionWith(client, cols, rows, rec, SessionOpts{})
}

// StartSessionOpts starts a remote shell with optional agent forwarding.
func StartSessionOpts(client *ssh.Client, cols, rows int, rec *Recorder, agentUpstream ssh.Conn) (*Bridge, error) {
	return StartSessionWith(client, cols, rows, rec, SessionOpts{AgentUpstream: agentUpstream})
}

func StartSessionWith(client *ssh.Client, cols, rows int, rec *Recorder, opts SessionOpts) (*Bridge, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	echo := uint32(1)
	if opts.QuietEcho || opts.Guard != nil {
		echo = 0
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          echo,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if opts.AgentUpstream != nil {
		agentChans := client.HandleChannelOpen("auth-agent@openssh.com")
		go bridgeAgentChannels(agentChans, opts.AgentUpstream)
		if ok, err := sess.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || !ok {
			_ = err
		}
	}
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, err
	}
	b := &Bridge{
		Client: client, Session: sess, Recorder: rec,
		stdinPipe: stdin, stdout: stdout, stderr: stderr,
		Guard: opts.Guard, LocalInject: opts.LocalInject, OnDenied: opts.OnDenied,
	}
	return b, nil
}

func bridgeAgentChannels(chans <-chan ssh.NewChannel, upstream ssh.Conn) {
	for nc := range chans {
		go func(nc ssh.NewChannel) {
			ch, reqs, err := nc.Accept()
			if err != nil {
				return
			}
			defer ch.Close()
			go ssh.DiscardRequests(reqs)

			up, upReqs, err := upstream.OpenChannel("auth-agent@openssh.com", nil)
			if err != nil {
				return
			}
			defer up.Close()
			go ssh.DiscardRequests(upReqs)

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(up, ch)
				_ = up.CloseWrite()
			}()
			go func() {
				defer wg.Done()
				_, _ = io.Copy(ch, up)
				_ = ch.CloseWrite()
			}()
			wg.Wait()
		}(nc)
	}
}

func (b *Bridge) Write(p []byte) (int, error) {
	if b.Guard != nil {
		if b.Guard.Notify == nil {
			b.Guard.Notify = func(chunk []byte) {
				if len(chunk) == 0 {
					return
				}
				if b.LocalInject != nil {
					b.LocalInject(chunk)
				}
				if b.Recorder != nil {
					b.Recorder.WriteOutput(chunk)
				}
			}
		}
		forward, echo, denied := b.Guard.Feed(p)
		if len(echo) > 0 {
			if b.LocalInject != nil {
				b.LocalInject(echo)
			}
			if b.Recorder != nil {
				b.Recorder.WriteOutput(echo)
			}
		}
		if denied != "" {
			msg := "\r\n\x1b[31m[KeepPAM JEA] denied: " + denied + "\x1b[0m\r\n"
			if b.LocalInject != nil {
				b.LocalInject([]byte(msg))
			}
			if b.Recorder != nil {
				b.Recorder.WriteInput([]byte(denied + "\n"))
				b.Recorder.WriteOutput([]byte(msg))
			}
			if b.OnDenied != nil {
				b.OnDenied(denied)
			}
		}
		if len(forward) > 0 {
			if b.Recorder != nil && denied == "" {
				b.Recorder.WriteInput(forward)
			}
			if _, err := b.stdinPipe.Write(forward); err != nil {
				return len(p), err
			}
		}
		return len(p), nil
	}
	if b.Recorder != nil {
		b.Recorder.WriteInput(p)
	}
	return b.stdinPipe.Write(p)
}

func (b *Bridge) Resize(cols, rows int) error {
	return b.Session.WindowChange(rows, cols)
}

func (b *Bridge) CopyOutput(dst io.Writer) error {
	var (
		mu     sync.Mutex
		outErr error
		wg     sync.WaitGroup
	)
	copyOne := func(r io.Reader) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if b.Recorder != nil {
					b.Recorder.WriteOutput(chunk)
				}
				mu.Lock()
				_, werr := dst.Write(chunk)
				mu.Unlock()
				if werr != nil {
					mu.Lock()
					outErr = werr
					mu.Unlock()
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					mu.Lock()
					outErr = err
					mu.Unlock()
				}
				return
			}
		}
	}
	wg.Add(2)
	go copyOne(b.stdout)
	go copyOne(b.stderr)
	wg.Wait()
	return outErr
}

func (b *Bridge) Close() {
	if b.stdinPipe != nil {
		_ = b.stdinPipe.Close()
	}
	if b.Session != nil {
		_ = b.Session.Close()
	}
	if b.Client != nil {
		_ = b.Client.Close()
	}
	if b.Recorder != nil {
		_ = b.Recorder.Close()
	}
}
