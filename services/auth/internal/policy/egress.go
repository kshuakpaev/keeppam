package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

const (
	maxEgressRules   = 32
	maxEgressRuleLen = 128
)

// lookupIPFn is net.LookupIP; tests may replace it.
var lookupIPFn = net.LookupIP

type egressRule struct {
	Host  string // lowercase hostname; empty if CIDR/IP
	IPNet *net.IPNet
	Port  int // 0 = any
	Raw   string
}

// ValidateEgress normalizes dest allowlist rules: host[:port], cidr[:port], ip[:port].
// Empty list is valid (deny-by-default for SSH tunnels). Loopback / link-local / localhost rejected.
func ValidateEgress(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r, err := parseEgressRule(s)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[r.Raw]; ok {
			continue
		}
		seen[r.Raw] = struct{}{}
		out = append(out, r.Raw)
	}
	if len(out) > maxEgressRules {
		return nil, fmt.Errorf("allowed_egress: max %d rules", maxEgressRules)
	}
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}

func parseEgressRule(s string) (egressRule, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxEgressRuleLen {
		return egressRule{}, fmt.Errorf("invalid egress rule %q", s)
	}
	hostPart := s
	port := 0
	switch {
	case strings.HasPrefix(s, "["):
		closeBr := strings.Index(s, "]")
		if closeBr < 2 {
			return egressRule{}, fmt.Errorf("invalid egress rule %q", s)
		}
		hostPart = s[1:closeBr]
		rest := s[closeBr+1:]
		if rest == "" {
			break
		}
		if !strings.HasPrefix(rest, ":") {
			return egressRule{}, fmt.Errorf("invalid egress rule %q", s)
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil {
			return egressRule{}, fmt.Errorf("invalid egress port in %q", s)
		}
		port = p
	case strings.Contains(s, "/"):
		slash := strings.Index(s, "/")
		lastColon := strings.LastIndex(s, ":")
		if lastColon > slash {
			hostPart = s[:lastColon]
			p, err := strconv.Atoi(s[lastColon+1:])
			if err != nil {
				return egressRule{}, fmt.Errorf("invalid egress port in %q", s)
			}
			port = p
		}
	default:
		if net.ParseIP(s) == nil {
			if h, pstr, err := net.SplitHostPort(s); err == nil {
				hostPart = h
				p, err := strconv.Atoi(pstr)
				if err != nil {
					return egressRule{}, fmt.Errorf("invalid egress port in %q", s)
				}
				port = p
			}
		}
	}
	if port < 0 || port > 65535 {
		return egressRule{}, fmt.Errorf("invalid egress port in %q", s)
	}
	r := egressRule{Port: port}
	if strings.Contains(hostPart, "/") {
		_, n, err := net.ParseCIDR(hostPart)
		if err != nil {
			return egressRule{}, fmt.Errorf("invalid egress CIDR %q", s)
		}
		r.IPNet = n
		r.Raw = n.String()
	} else if ip := net.ParseIP(hostPart); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		r.IPNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		r.Raw = ip.String()
	} else {
		h := strings.ToLower(hostPart)
		if !validEgressHostname(h) {
			return egressRule{}, fmt.Errorf("invalid egress host %q", s)
		}
		r.Host = h
		r.Raw = h
	}
	if port > 0 {
		r.Raw += ":" + strconv.Itoa(port)
	}
	if egressRuleBlocked(r) {
		return egressRule{}, fmt.Errorf("egress destination blocked: %s", r.Raw)
	}
	return r, nil
}

func validEgressHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.Contains(h, "..") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// BlockedEgressIP is the worker-side SSRF guard (loopback / link-local / multicast).
func BlockedEgressIP(ip net.IP) bool {
	return blockedIP(ip)
}

func egressRuleBlocked(r egressRule) bool {
	switch r.Host {
	case "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback":
		return true
	}
	if r.IPNet == nil {
		return false
	}
	ones, bits := r.IPNet.Mask.Size()
	if ones == bits {
		return blockedIP(r.IPNet.IP)
	}
	return r.IPNet.IP.IsLoopback() || r.IPNet.IP.IsLinkLocalUnicast()
}

// MatchEgress reports whether dest host:port is covered by the allowlist.
// Empty rules → false (tunnels stay deny-by-default, unlike allowed_cidrs).
func MatchEgress(rules []string, destHost string, destPort int) bool {
	if destPort < 1 || destPort > 65535 {
		return false
	}
	destHost = strings.TrimSpace(destHost)
	if destHost == "" || len(rules) == 0 {
		return false
	}
	destIP := net.ParseIP(destHost)
	var resolved []net.IP
	lookedUp := false
	for _, raw := range rules {
		r, err := parseEgressRule(raw)
		if err != nil {
			continue
		}
		if r.Port != 0 && r.Port != destPort {
			continue
		}
		if r.Host != "" {
			if strings.EqualFold(r.Host, destHost) {
				return true
			}
			continue
		}
		if r.IPNet == nil {
			continue
		}
		if destIP != nil {
			if r.IPNet.Contains(destIP) {
				return true
			}
			continue
		}
		if !lookedUp {
			resolved, _ = lookupIPFn(destHost)
			lookedUp = true
		}
		for _, ip := range resolved {
			if r.IPNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// AllowSSHEgress is the in-session check for SSH direct-tcpip.
// Empty AllowedEgress denies (current DLP). Break-glass / admin bypass skip the list.
func AllowSSHEgress(snap Snapshot, host string, port int) (reason string, deny bool) {
	if snap.BreakGlass || snap.AdminBypass {
		return "", false
	}
	if len(snap.AllowedEgress) == 0 {
		return "ssh port-forward denied by DLP", true
	}
	if !MatchEgress(snap.AllowedEgress, host, port) {
		return "ssh egress destination not allowed", true
	}
	return "", false
}
