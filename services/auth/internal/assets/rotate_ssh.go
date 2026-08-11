package assets

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshRun(client *ssh.Client, cmd string) (string, string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	err = session.Run(cmd)
	return stdout.String(), stderr.String(), err
}

func changeRemotePassword(client *ssh.Client, username, oldPass, newPass string) error {
	uidOut, _, err := sshRun(client, "id -u")
	if err != nil {
		return fmt.Errorf("id -u: %w", err)
	}
	uid := strings.TrimSpace(uidOut)

	if uid == "0" {
		return chpasswd(client, username, newPass)
	}

	meOut, _, err := sshRun(client, "id -un")
	if err != nil {
		return fmt.Errorf("id -un: %w", err)
	}
	me := strings.TrimSpace(meOut)
	if me != username {
		return fmt.Errorf("non-root cannot rotate other user %q (logged in as %q)", username, me)
	}

	if err := passwdStdin(client, newPass); err == nil {
		return nil
	}
	if err := chpasswd(client, me, newPass); err == nil {
		return nil
	}
	if err := passwdPTY(client, oldPass, newPass); err != nil {
		return fmt.Errorf("passwd: %w", err)
	}
	return nil
}

func changeWindowsPassword(client *ssh.Client, username, newPass string) error {
	cmd := fmt.Sprintf("net user %s %s", shellQuoteWin(username), shellQuoteWin(newPass))
	_, stderr, err := sshRun(client, cmd)
	if err != nil {
		ps := fmt.Sprintf(
			`powershell -NoProfile -Command "$p=ConvertTo-SecureString %s -AsPlainText -Force; Set-LocalUser -Name %s -Password $p"`,
			shellQuoteWin(newPass), shellQuoteWin(username),
		)
		_, stderr2, err2 := sshRun(client, ps)
		if err2 != nil {
			return fmt.Errorf("%v (%s); powershell: %v (%s)", err, truncate(stderr, 120), err2, truncate(stderr2, 120))
		}
	}
	return nil
}

func chpasswd(client *ssh.Client, username, newPass string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Start("chpasswd"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdin, "%s:%s\n", username, newPass); err != nil {
		return err
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()+" "+err.Error()))
	}
	return nil
}

func passwdStdin(client *ssh.Client, newPass string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Start("passwd --stdin"); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, newPass+"\n"); err != nil {
		return err
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func passwdPTY(client *ssh.Client, oldPass, newPass string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("vt100", 40, 80, modes); err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf
	if err := session.Start("passwd"); err != nil {
		return err
	}

	deadline := time.Now().Add(20 * time.Second)
	sentOld, sentNew, sentConfirm := false, false, false
	for time.Now().Before(deadline) && (!sentOld || !sentNew || !sentConfirm) {
		time.Sleep(200 * time.Millisecond)
		low := strings.ToLower(buf.String())
		switch {
		case !sentOld && (strings.Contains(low, "current") || strings.Contains(low, "old") || strings.Contains(low, "(current)")):
			if _, err := io.WriteString(stdin, oldPass+"\n"); err != nil {
				return err
			}
			sentOld = true
		case sentOld && !sentNew && strings.Contains(low, "new"):
			if _, err := io.WriteString(stdin, newPass+"\n"); err != nil {
				return err
			}
			sentNew = true
		case sentNew && !sentConfirm && (strings.Contains(low, "retype") || strings.Contains(low, "again") || strings.Contains(low, "confirm") || strings.Count(low, "new") >= 2):
			if _, err := io.WriteString(stdin, newPass+"\n"); err != nil {
				return err
			}
			sentConfirm = true
		}
	}
	if !sentOld && !sentNew {
		_, _ = io.WriteString(stdin, oldPass+"\n"+newPass+"\n"+newPass+"\n")
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%s", truncate(buf.String()+" "+err.Error(), 300))
	}
	out := strings.ToLower(buf.String())
	if strings.Contains(out, "unchanged") || strings.Contains(out, "failure") || strings.Contains(out, "incorrect") || strings.Contains(out, "authentication token manipulation error") {
		return fmt.Errorf("%s", truncate(buf.String(), 300))
	}
	return nil
}

func installAuthorizedKey(client *ssh.Client, pubLine string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	cmd := `bash -c 'mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" && KEY=$(cat) && grep -qxF "$KEY" "$HOME/.ssh/authorized_keys" || printf "%s\n" "$KEY" >> "$HOME/.ssh/authorized_keys"'`
	if err := session.Start(cmd); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, pubLine+"\n"); err != nil {
		return err
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func removeAuthorizedKey(client *ssh.Client, pubLine string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr
	cmd := `bash -c 'KEY=$(cat); f="$HOME/.ssh/authorized_keys"; [ -f "$f" ] || exit 0; grep -vxF "$KEY" "$f" > "$f.tmp" || true; mv "$f.tmp" "$f"'`
	if err := session.Start(cmd); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, pubLine+"\n"); err != nil {
		return err
	}
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellQuoteWin(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
