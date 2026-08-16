package geoip

import (
	"net"
	"net/http"
	"strings"
)

func ParseProxyCIDRs(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			if _, _, err := net.ParseCIDR(p); err == nil {
				out = append(out, p)
			}
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			out = append(out, ip.String()+"/32")
		} else {
			out = append(out, ip.String()+"/128")
		}
	}
	return out
}

func trustedAddr(addr string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return false
	}
	ip := ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func headerClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := ParseIP(first); ip != nil {
			return ip.String()
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		if ip := ParseIP(xr); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}
	return host
}

// RequestClientIP uses X-Forwarded-For / X-Real-IP only when RemoteAddr is in trusted CIDRs.
func RequestClientIP(r *http.Request, trustedCIDRs []string) string {
	if r == nil {
		return ""
	}
	host := remoteHost(r.RemoteAddr)
	if trustedAddr(host, trustedCIDRs) {
		if ip := headerClientIP(r); ip != "" {
			return ip
		}
	}
	return host
}
