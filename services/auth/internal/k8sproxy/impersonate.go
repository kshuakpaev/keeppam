package k8sproxy

import (
	"net/http"
	"strings"
)

const defaultImpersonatePrefix = "keeppam:"

func CanonImpersonatePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == defaultImpersonatePrefix {
		return defaultImpersonatePrefix
	}
	if p == "-" || strings.EqualFold(p, "none") {
		return ""
	}
	return p
}

func ImpersonateUser(prefix, pamUsername string) string {
	u := strings.TrimSpace(pamUsername)
	if u == "" {
		return ""
	}
	return CanonImpersonatePrefix(prefix) + u
}

func ImpersonateGroups(roles []string) []string {
	out := []string{"system:authenticated", "keeppam:users"}
	seen := map[string]struct{}{
		"system:authenticated": {},
		"keeppam:users":        {},
	}
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		g := "keeppam:role:" + r
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

func ApplyImpersonate(h http.Header, user string, groups []string, extraUID string) {
	if h == nil || strings.TrimSpace(user) == "" {
		return
	}
	h.Set("Impersonate-User", user)
	h.Del("Impersonate-Group")
	for _, g := range groups {
		if strings.TrimSpace(g) == "" {
			continue
		}
		h.Add("Impersonate-Group", g)
	}
	if uid := strings.TrimSpace(extraUID); uid != "" {
		h.Set("Impersonate-Extra-keeppam-uid", uid)
	}
}
