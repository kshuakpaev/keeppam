package firewall

import (
	"fmt"
	"strings"
)

// Target is a lightweight asset row for pam-only enforcement.
type Target struct {
	Name     string
	Address  string
	Hostname string
	Port     int
	Protocol string
	PamOnly  bool
}

// ExportTarget is an active pam-only asset for rule generation.
type ExportTarget struct {
	Name     string
	Address  string
	Port     int
	Protocol string
}

func HostMatches(host, address, hostname string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(address), host) {
		return true
	}
	if hostname != "" && strings.EqualFold(strings.TrimSpace(hostname), host) {
		return true
	}
	return false
}

// PamOnlyForwardBlocked denies SSH port-forward to another pam-only asset on its service port.
func PamOnlyForwardBlocked(host string, port int, targets []Target) (reason string, block bool) {
	for _, t := range targets {
		if !t.PamOnly || port != t.Port || !HostMatches(host, t.Address, t.Hostname) {
			continue
		}
		switch t.Protocol {
		case "ssh", "rdp", "vnc", "https", "kubectl", "postgres", "mysql", "mssql", "oracle", "telnet", "tn3270", "citrix", "ftp":
			return fmt.Sprintf("pam-only asset %q: connect via PAM, not port-forward", t.Name), true
		}
	}
	return "", false
}
