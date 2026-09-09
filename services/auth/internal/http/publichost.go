package httpapi

import (
	"net"
	"net/http"
	"strings"
)

// clientFacingHost picks the hostname clients should put in .rdp / SSH config.
// An explicit non-loopback KEEPPAM_*_PUBLIC_HOST wins; otherwise the request
// Host (or X-Forwarded-Host) is preferred over localhost/127.0.0.1 so that
// compose defaults of "localhost" still produce a reachable address when the
// portal is opened by IP/FQDN.
func clientFacingHost(configured string, r *http.Request) string {
	cfg := strings.TrimSpace(configured)
	if strings.EqualFold(cfg, "off") {
		cfg = ""
	}
	req := hostFromRequest(r)
	if cfg != "" && !isLoopbackHost(cfg) {
		return cfg
	}
	if req != "" && !isLoopbackHost(req) {
		return req
	}
	if cfg != "" {
		return cfg
	}
	if req != "" {
		return req
	}
	return "localhost"
}

func hostFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if raw == "" {
		raw = strings.TrimSpace(r.Host)
	} else if i := strings.IndexByte(raw, ','); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	if raw == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return strings.Trim(raw, "[]")
}

func isLoopbackHost(h string) bool {
	h = strings.TrimSpace(strings.ToLower(h))
	switch h {
	case "", "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
