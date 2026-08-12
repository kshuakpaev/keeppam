package policy

import (
	"fmt"
	"net"
	"strings"
)

func normalizeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func validateCIDRs(in []string) ([]string, error) {
	out := normalizeCIDRs(in)
	for _, c := range out {
		if strings.Contains(c, "/") {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", c)
			}
			continue
		}
		if net.ParseIP(c) == nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q", c)
		}
	}
	return out, nil
}

func ipAllowed(cidrs []string, clientIP string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		// X-Forwarded-For may include port or be empty
		host, _, err := net.SplitHostPort(strings.TrimSpace(clientIP))
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			if n.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(c); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}
