package winrm

import (
	"context"
	"fmt"
	"strings"
	"time"

	w "github.com/masterzen/winrm"
)

const (
	DefaultHTTPPort  = 5985
	DefaultHTTPSPort = 5986
	runTimeout       = 45 * time.Second
)

func runPS(host string, port int, useHTTPS, insecure bool, user, pass, script string) (string, error) {
	if port <= 0 {
		if useHTTPS {
			port = DefaultHTTPSPort
		} else {
			port = DefaultHTTPPort
		}
	}
	endpoint := w.NewEndpoint(host, port, useHTTPS, insecure, nil, nil, nil, runTimeout)
	params := w.NewParameters("PT45S", "", 0)
	client, err := w.NewClientWithParameters(endpoint, user, pass, params)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	stdout, stderr, exit, err := client.RunPSWithContext(ctx, script)
	if err != nil {
		if msg := strings.TrimSpace(stderr); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	if exit != 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = strings.TrimSpace(stdout)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", exit)
		}
		return "", fmt.Errorf("winrm exit %d: %s", exit, msg)
	}
	return stdout, nil
}

// RunPowerShell executes a script via WinRM (HTTP 5985) and returns combined stdout.
func RunPowerShell(host string, port int, useHTTPS, insecure bool, user, pass, script string) (string, error) {
	return runPS(host, port, useHTTPS, insecure, user, pass, script)
}

// RunPowerShellTLS executes a script via WinRM over HTTPS (5986), skipping cert verify in lab.
func RunPowerShellTLS(host string, port int, user, pass, script string) (string, error) {
	return runPS(host, port, true, true, user, pass, script)
}

// NormalizeHost strips port suffix from address.
func NormalizeHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr, "]") {
		return addr[:i]
	}
	return addr
}
