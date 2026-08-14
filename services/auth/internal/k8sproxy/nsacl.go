package k8sproxy

import (
	"fmt"
	"strings"
	"unicode"
)

func NormalizeNamespaces(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range in {
		n := strings.ToLower(strings.TrimSpace(raw))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func ValidateNamespaces(in []string) ([]string, error) {
	out := NormalizeNamespaces(in)
	for _, n := range out {
		if !validDNSLabel(n) {
			return nil, fmt.Errorf("invalid namespace %q (DNS-1123 label)", n)
		}
	}
	return out, nil
}

func validDNSLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		if unicode.IsLetter(r) {
			return false
		}
		return false
	}
	return true
}

var discoveryResources = map[string]bool{
	"": true, "root": true, "api": true, "apis": true,
	"version": true, "healthz": true, "livez": true, "readyz": true, "openapi": true,
}

// NamespaceAllowed enforces binding ACL. Empty allowlist = any namespace (and cluster scope).
func NamespaceAllowed(allowed []string, call APICall) (ok bool, reason string) {
	allowed = NormalizeNamespaces(allowed)
	if len(allowed) == 0 {
		return true, ""
	}
	res := strings.ToLower(strings.TrimSpace(call.Resource))
	if discoveryResources[res] {
		return true, ""
	}
	grp := strings.ToLower(strings.TrimSpace(call.APIGroup))
	if grp == "authorization.k8s.io" && (res == "selfsubjectaccessreviews" || res == "selfsubjectrulesreviews") {
		return true, ""
	}
	if grp == "authentication.k8s.io" && res == "selfsubjectreviews" {
		return true, ""
	}
	ns := strings.ToLower(strings.TrimSpace(call.Namespace))
	if ns == "" && res == "namespaces" && strings.TrimSpace(call.Name) != "" {
		ns = strings.ToLower(strings.TrimSpace(call.Name))
	}
	if ns != "" {
		for _, a := range allowed {
			if a == ns {
				return true, ""
			}
		}
		return false, "namespace_acl"
	}
	if res == "namespaces" && strings.TrimSpace(call.Name) == "" && !call.Watch && (call.Verb == "list" || call.Verb == "get") {
		return true, "filter_namespaces"
	}
	return false, "cluster_scope_denied"
}

func NeedsNamespaceListFilter(allowed []string, call APICall) bool {
	allowed = NormalizeNamespaces(allowed)
	if len(allowed) == 0 {
		return false
	}
	res := strings.ToLower(strings.TrimSpace(call.Resource))
	return res == "namespaces" && strings.TrimSpace(call.Namespace) == "" && strings.TrimSpace(call.Name) == "" && !call.Watch && (call.Verb == "list" || call.Verb == "get")
}
