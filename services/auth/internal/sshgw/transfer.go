package sshgw

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/filexfer"
	"github.com/keeppam/auth/internal/policy"
)

type fileXferKind struct {
	scp  bool
	sftp bool
	sink bool
	dest string
	raw  string
}

func parseFileXferStart(execCmd, subsystem string) (fileXferKind, bool) {
	if strings.EqualFold(strings.TrimSpace(subsystem), "sftp") {
		return fileXferKind{sftp: true, raw: "subsystem:sftp"}, true
	}
	if sink, dest, ok := policy.ParseSCPExec(execCmd); ok {
		return fileXferKind{scp: true, sink: sink, dest: dest, raw: execCmd}, true
	}
	return fileXferKind{}, false
}

func splitSSHLogin(user string) (login, hint string) {
	i := strings.LastIndex(user, "+")
	if i <= 0 || i == len(user)-1 {
		return user, ""
	}
	return user[:i], user[i+1:]
}

func resolveTransferDest(targets []targetRef, dest, hint string) (*targetRef, string, error) {
	dest = strings.Trim(strings.TrimSpace(dest), "/")
	if dest == "" || dest == "." {
		dest = strings.TrimSpace(hint)
	}
	if dest == "" || dest == "." {
		if len(targets) == 1 {
			t := targets[0]
			return &t, ".", nil
		}
		return nil, "", fmt.Errorf("specify asset (scp user@gw:ASSET[/path] or login user+ASSET)")
	}
	if t, err := resolveTarget(targets, dest); err == nil {
		return t, ".", nil
	}
	parts := strings.Split(dest, "/")
	if t, err := resolveTarget(targets, parts[0]); err == nil {
		rem := strings.Join(parts[1:], "/")
		if rem == "" {
			rem = "."
		}
		return t, rem, nil
	}
	if len(parts) >= 2 {
		if t, err := resolveTarget(targets, parts[0]+"/"+parts[1]); err == nil {
			rem := strings.Join(parts[2:], "/")
			if rem == "" {
				rem = "."
			}
			return t, rem, nil
		}
	}
	return nil, "", fmt.Errorf("target not found or denied: %s", dest)
}

func (g *Gateway) runSCP(ctx context.Context, ch ssh.Channel, client *ssh.Client, sessionID uuid.UUID, remotePath string, sink, capture bool) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	if err := sess.Start(filexfer.RemoteSCPCommand(sink, remotePath)); err != nil {
		return err
	}
	var parseUp, parseDown io.Writer
	done := make(chan struct{})
	if g.files != nil {
		pr, pw := io.Pipe()
		dir := "download"
		if sink {
			dir = "upload"
			parseUp = pw
		} else {
			parseDown = pw
		}
		go func() {
			_ = g.files.CaptureSCP(ctx, sessionID, capture, dir, pr)
			close(done)
		}()
		defer func() { _ = pw.Close(); <-done }()
	}
	err = filexfer.CopySCP(ch, stdin, stdout, parseUp, parseDown)
	_ = sess.Wait()
	return err
}

func (g *Gateway) runSFTP(ctx context.Context, ch ssh.Channel, client *ssh.Client, sessionID uuid.UUID, capture bool) error {
	rch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)
	defer rch.Close()
	ok, err := rch.SendRequest("subsystem", true, ssh.Marshal(struct{ Subsystem string }{"sftp"}))
	if err != nil || !ok {
		return fmt.Errorf("remote sftp subsystem refused")
	}
	if g.files == nil {
		_, _ = io.Copy(rch, ch)
		return nil
	}
	return g.files.CopySFTP(ctx, sessionID, capture, ch, rch)
}
