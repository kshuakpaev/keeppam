package sshgw

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ConnFileOpts builds an OpenSSH connection configuration for KeepPAM SSH gateway.
// Client authenticates to the gateway with PAM credentials (password or user SSH key);
// vault secrets for the target are never included.
type ConnFileOpts struct {
	PublicHost   string // PAM hostname clients use (e.g. pam.example.com)
	Port         int    // gateway listen port (default 2222)
	PAMUser      string // KeepPAM login (portal username)
	AssetName    string // asset name as shown in gateway target menu
	AccountName  string // vault account username on the asset
	IdentityFile string // optional path hint for operator key (comment only if empty)
	IncludePutty bool   // append PuTTY-oriented notes in the same file
	// WireUser / WirePass: portal native client (session UUID + one-time token) for putty -pw.
	WireUser string
	WirePass string
}

// ParseSSHPort extracts TCP port from addr like ":2222" or "0.0.0.0:2222".
func ParseSSHPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 2222
	}
	if strings.HasPrefix(addr, ":") {
		p, err := strconv.Atoi(strings.TrimPrefix(addr, ":"))
		if err == nil && p > 0 {
			return p
		}
		return 2222
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 2222
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 {
		return 2222
	}
	return p
}

func sanitizeHostAlias(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ', r == '.', r == '/', r == '\\', r == '+':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "keeppam-target"
	}
	return out
}

// TargetSpec is "asset/account" for gateway RemoteCommand / -t.
func TargetSpec(assetName, accountName string) string {
	a := strings.TrimSpace(assetName)
	c := strings.TrimSpace(accountName)
	if a == "" {
		return c
	}
	if c == "" {
		return a
	}
	return a + "/" + c
}

// BuildSSHConfigFile returns OpenSSH config body suitable for Include or copy into ~/.ssh/config.
func BuildSSHConfigFile(o ConnFileOpts) string {
	host := strings.TrimSpace(o.PublicHost)
	if host == "" {
		host = "localhost"
	}
	port := o.Port
	if port <= 0 {
		port = 2222
	}
	pam := strings.TrimSpace(o.PAMUser)
	if pam == "" {
		pam = "USER"
	}
	target := TargetSpec(o.AssetName, o.AccountName)
	alias := "keeppam-" + sanitizeHostAlias(o.AssetName)
	if o.AccountName != "" {
		alias += "-" + sanitizeHostAlias(o.AccountName)
	}

	var b strings.Builder
	b.WriteString("# KeepPAM SSH connection file — authenticate with your PAM password or SSH key.\n")
	b.WriteString("# Target credentials stay in the vault; they are not in this file.\n")
	b.WriteString("# Usage: ssh " + alias + "\n")
	b.WriteString("# Or:    ssh -F thisfile " + alias + "\n")
	b.WriteString("#\n")
	fmt.Fprintf(&b, "# One-liner: ssh -p %d -t %s@%s '%s'\n\n", port, pam, host, target)

	fmt.Fprintf(&b, "Host %s\n", alias)
	fmt.Fprintf(&b, "  HostName %s\n", host)
	fmt.Fprintf(&b, "  Port %d\n", port)
	fmt.Fprintf(&b, "  User %s\n", pam)
	b.WriteString("  RequestTTY force\n")
	fmt.Fprintf(&b, "  RemoteCommand %s\n", target)
	if id := strings.TrimSpace(o.IdentityFile); id != "" {
		fmt.Fprintf(&b, "  IdentityFile %s\n", id)
		b.WriteString("  IdentitiesOnly yes\n")
	}
	b.WriteString("  ForwardAgent no\n")
	b.WriteString("\n")

	if o.IncludePutty {
		b.WriteString("# --- PuTTY / MobaXterm ---\n")
		fmt.Fprintf(&b, "# Host: %s  Port: %d\n", host, port)
		fmt.Fprintf(&b, "# Username: %s\n", pam)
		fmt.Fprintf(&b, "# Remote command: %s\n", target)
		b.WriteString("# Password or private key: your KeepPAM account (not the target vault secret).\n")
		b.WriteString("\n")
	}
	return b.String()
}

// HostAlias is the OpenSSH Host name used in BuildSSHConfigFile.
func HostAlias(assetName, accountName string) string {
	alias := "keeppam-" + sanitizeHostAlias(assetName)
	if accountName != "" {
		alias += "-" + sanitizeHostAlias(accountName)
	}
	return alias
}

// BuildSSHLauncherCMD is a Windows Native Client Launcher that starts PuTTY (Fudo-style).
// Falls back message if putty.exe is not installed. OpenSSH config remains a separate download.
func BuildSSHLauncherCMD(o ConnFileOpts) string {
	return BuildPuTTYLauncherCMD(o)
}

// BuildPuTTYLauncherCMD locates putty.exe and opens an SSH session to the KeepPAM gateway.
// With WirePass set (Fudo-style): putty -pw <token>, user = session UUID — no password prompt.
// Otherwise: PAM user login; operator types KeepPAM password.
func BuildPuTTYLauncherCMD(o ConnFileOpts) string {
	host := strings.TrimSpace(o.PublicHost)
	if host == "" {
		host = "localhost"
	}
	port := o.Port
	if port <= 0 {
		port = 2222
	}
	pam := strings.TrimSpace(o.PAMUser)
	if pam == "" {
		pam = "USER"
	}
	login := pam
	if w := strings.TrimSpace(o.WireUser); w != "" {
		login = w
	}
	target := TargetSpec(o.AssetName, o.AccountName)
	wirePass := strings.TrimSpace(o.WirePass)
	psQuote := func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	}

	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("setlocal EnableExtensions\r\n")
	b.WriteString("REM KeepPAM Native Client Launcher — PuTTY (Fudo-style auto password)\r\n")
	if wirePass != "" {
		b.WriteString("REM Password = one-time wire token (not vault secret).\r\n")
	} else {
		b.WriteString("REM Enter KeepPAM account password in PuTTY (vault secret stays on gateway).\r\n")
	}
	fmt.Fprintf(&b, "set \"KP_HOST=%s\"\r\n", host)
	fmt.Fprintf(&b, "set \"KP_PORT=%d\"\r\n", port)
	fmt.Fprintf(&b, "set \"KP_USER=%s\"\r\n", login)
	fmt.Fprintf(&b, "set \"KP_TARGET=%s\"\r\n", target)
	if wirePass != "" {
		fmt.Fprintf(&b, "set \"KP_PASS=%s\"\r\n", wirePass)
	}
	b.WriteString("set \"KP_RC=%TEMP%\\keeppam-ssh-%RANDOM%%RANDOM%.txt\"\r\n")
	fmt.Fprintf(&b,
		"powershell -NoProfile -ExecutionPolicy Bypass -Command \"Set-Content -LiteralPath $env:KP_RC -Value '%s' -NoNewline -Encoding ascii\"\r\n",
		psQuote(target))
	b.WriteString("set \"PUTTY=\"\r\n")
	b.WriteString("where putty.exe >nul 2>&1 && for /f \"delims=\" %%P in ('where putty.exe') do if not defined PUTTY set \"PUTTY=%%P\"\r\n")
	b.WriteString("if not defined PUTTY if exist \"%ProgramFiles%\\PuTTY\\putty.exe\" set \"PUTTY=%ProgramFiles%\\PuTTY\\putty.exe\"\r\n")
	b.WriteString("if not defined PUTTY if exist \"%ProgramFiles(x86)%\\PuTTY\\putty.exe\" set \"PUTTY=%ProgramFiles(x86)%\\PuTTY\\putty.exe\"\r\n")
	b.WriteString("if not defined PUTTY if exist \"%LOCALAPPDATA%\\Programs\\PuTTY\\putty.exe\" set \"PUTTY=%LOCALAPPDATA%\\Programs\\PuTTY\\putty.exe\"\r\n")
	b.WriteString("if not defined PUTTY (\r\n")
	b.WriteString("  echo KeepPAM: PuTTY не найден. Установите https://www.putty.org/ ^(или WinSCP+PuTTY^).\r\n")
	b.WriteString("  pause\r\n")
	b.WriteString("  exit /b 1\r\n")
	b.WriteString(")\r\n")
	if wirePass != "" {
		b.WriteString("start \"KeepPAM PuTTY\" \"%PUTTY%\" -ssh %KP_USER%@%KP_HOST% -P %KP_PORT% -pw %KP_PASS% -m \"%KP_RC%\"\r\n")
	} else {
		b.WriteString("start \"KeepPAM PuTTY\" \"%PUTTY%\" -ssh %KP_USER%@%KP_HOST% -P %KP_PORT% -m \"%KP_RC%\"\r\n")
	}
	return b.String()
}

// BuildSSHLauncherSH is a Unix Native Client Launcher (.sh) next to the .sshconfig.
func BuildSSHLauncherSH(configFilename, hostAlias string) string {
	cfg := strings.TrimSpace(configFilename)
	if cfg == "" {
		cfg = "keeppam.sshconfig"
	}
	alias := strings.TrimSpace(hostAlias)
	if alias == "" {
		alias = "keeppam-target"
	}
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# KeepPAM Native Client Launcher (SSH / OpenSSH)\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n")
	fmt.Fprintf(&b, "exec ssh -F \"$DIR/%s\" %s\n", cfg, alias)
	return b.String()
}

// LauncherFilenameCMD / SH for Content-Disposition.
func LauncherFilenameCMD(assetName, accountName string) string {
	return strings.TrimSuffix(ConnFilename(assetName, accountName), ".sshconfig") + "-putty.cmd"
}

func LauncherFilenameSH(assetName, accountName string) string {
	return strings.TrimSuffix(ConnFilename(assetName, accountName), ".sshconfig") + ".sh"
}

// BuildSSHHint is a short UI / wire_hint line.
func BuildSSHHint(o ConnFileOpts) string {
	host := strings.TrimSpace(o.PublicHost)
	if host == "" {
		host = "localhost"
	}
	port := o.Port
	if port <= 0 {
		port = 2222
	}
	pam := strings.TrimSpace(o.PAMUser)
	if pam == "" {
		pam = "USER"
	}
	target := TargetSpec(o.AssetName, o.AccountName)
	if strings.TrimSpace(o.WirePass) != "" {
		return fmt.Sprintf("PuTTY auto-login → session %s@%s:%d (wire token). Запустите *-putty.cmd", shortID(o.WireUser), host, port)
	}
	return fmt.Sprintf("PuTTY → %s@%s:%d, remote: %s (пароль KeepPAM). Запустите *-putty.cmd", pam, host, port, target)
}

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

// Filename for Content-Disposition.
func ConnFilename(assetName, accountName string) string {
	base := sanitizeHostAlias(assetName)
	if accountName != "" {
		base += "-" + sanitizeHostAlias(accountName)
	}
	return fmt.Sprintf("keeppam-%s.sshconfig", base)
}
