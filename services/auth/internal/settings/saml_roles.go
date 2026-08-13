package settings

import (
	"sort"
	"strings"
)

// MapSAMLRoles maps IdP groups onto existing KeepPAM role names.
// Unknown roles are skipped. If the user already has admin, it is kept.
// Empty mapping means "do not sync" — caller should skip UpdateUser.
func MapSAMLRoles(groups []string, mapping map[string]string, current []string, defaultRole string, known map[string]struct{}) []string {
	if len(mapping) == 0 {
		return append([]string(nil), current...)
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := known[name]; !ok {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if role, ok := mapping[g]; ok {
			add(role)
		}
		// case-insensitive key fallback
		for k, role := range mapping {
			if strings.EqualFold(k, g) {
				add(role)
			}
		}
	}
	if len(out) == 0 {
		add(defaultRole)
	}
	for _, r := range current {
		if r == "admin" {
			add("admin")
		}
	}
	sort.Strings(out)
	return out
}

func ParseGroupRoleMap(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func RolesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
