package geoip

import (
	"net"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type Lookup struct {
	path string
	db   *maxminddb.Reader
}

func New(path string) *Lookup {
	l := &Lookup{path: strings.TrimSpace(path)}
	if l.path == "" {
		return l
	}
	db, err := maxminddb.Open(l.path)
	if err != nil {
		return l
	}
	l.db = db
	return l
}

func (l *Lookup) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

func (l *Lookup) Loaded() bool {
	return l != nil && l.db != nil
}

func ParseIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// Classify returns LAN for private/loopback/link-local, otherwise "".
func Classify(ipStr string) string {
	ip := ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return "LAN"
	}
	return ""
}

func (l *Lookup) Country(ipStr string) string {
	if c := Classify(ipStr); c != "" {
		return c
	}
	ip := ParseIP(ipStr)
	if ip == nil || l == nil || l.db == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := l.db.Lookup(ip, &rec); err != nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(rec.Country.ISOCode))
}

func NormalizeCountries(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
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

func ValidateCountries(in []string) ([]string, error) {
	out := NormalizeCountries(in)
	for _, c := range out {
		if c == "LAN" {
			continue
		}
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return nil, errCountry(c)
		}
	}
	return out, nil
}

type countryError string

func (e countryError) Error() string {
	return "invalid country code " + string(e) + " (use ISO 3166-1 alpha-2 or LAN)"
}

func errCountry(c string) error { return countryError(c) }

func Allowed(allowed []string, got string) bool {
	allowed = NormalizeCountries(allowed)
	if len(allowed) == 0 {
		return true
	}
	got = strings.ToUpper(strings.TrimSpace(got))
	for _, a := range allowed {
		if a == got {
			return true
		}
	}
	return false
}
