package policy

import (
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/google/uuid"
)

// AssetSelector is the WHAT side of a dynamic (asset_id NULL) ACL binding.
type AssetSelector struct {
	Tags     []string
	Mode     string // all|any for tags
	Name     string // glob, e.g. prod-*
	Hostname string // glob against hostname
	Types    []string
	CIDRs    []string
}

// AssetMeta is enough of an asset to evaluate a selector.
type AssetMeta struct {
	Name        string
	Hostname    string
	Address     string
	Type        string
	Tags        []string
	OwnerUserID *uuid.UUID
}

func (s AssetSelector) Empty() bool {
	return len(normalizeTags(s.Tags)) == 0 &&
		strings.TrimSpace(s.Name) == "" &&
		strings.TrimSpace(s.Hostname) == "" &&
		len(normalizeTypes(s.Types)) == 0 &&
		len(s.CIDRs) == 0
}

func normalizeTypes(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func normalizeNameGlob(s string) string {
	return strings.TrimSpace(s)
}

// MatchAsset returns true when all non-empty selector fields match the asset (AND).
func (s AssetSelector) MatchAsset(a AssetMeta) bool {
	if s.Empty() {
		return false
	}
	if tags := normalizeTags(s.Tags); len(tags) > 0 {
		if !tagsMatch(s.Mode, a.Tags, tags) {
			return false
		}
	}
	if g := normalizeNameGlob(s.Name); g != "" {
		if !matchGlob(g, a.Name) {
			return false
		}
	}
	if g := normalizeNameGlob(s.Hostname); g != "" {
		host := strings.TrimSpace(a.Hostname)
		if host == "" {
			host = strings.TrimSpace(a.Address)
		}
		if !matchGlob(g, host) {
			return false
		}
	}
	if types := normalizeTypes(s.Types); len(types) > 0 {
		at := strings.ToLower(strings.TrimSpace(a.Type))
		ok := false
		for _, t := range types {
			if t == at {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if cidrs := s.CIDRs; len(cidrs) > 0 {
		if !addressInCIDRs(a.Address, cidrs) {
			return false
		}
	}
	return true
}

func matchGlob(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

func addressInCIDRs(addr string, cidrs []string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	// Strip port if present.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if net.ParseIP(c) != nil && net.ParseIP(c).Equal(ip) {
				return true
			}
			continue
		}
		_, netw, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

func validateMatchCIDRs(in []string) ([]string, error) {
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return nil, fmt.Errorf("invalid asset_match_cidrs: %s", c)
			}
		} else if net.ParseIP(c) == nil {
			return nil, fmt.Errorf("invalid asset_match_cidrs: %s", c)
		}
		out = append(out, c)
	}
	return out, nil
}

// dynamicACLSQL: inherited binding with any WHAT selector (tags/name/host/type/cidr).
func dynamicACLSQL() string {
	return `(b.asset_id IS NULL AND (
		cardinality(COALESCE(b.asset_match_tags,'{}')) > 0
		OR COALESCE(b.asset_match_name,'') <> ''
		OR COALESCE(b.asset_match_hostname,'') <> ''
		OR cardinality(COALESCE(b.asset_match_types,'{}')) > 0
		OR cardinality(COALESCE(b.asset_match_cidrs,'{}')) > 0
	))`
}
