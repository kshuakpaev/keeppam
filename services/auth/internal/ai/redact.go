package ai

import (
	"regexp"
	"strings"
)

var (
	rePrivateKey = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	rePasswordKV = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+`)
	reBearer     = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	reEmail      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

const redacted = "***"

// Redact strips secrets from text before it reaches a model.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := rePrivateKey.ReplaceAllString(s, redacted)
	out = reBearer.ReplaceAllString(out, "Bearer "+redacted)
	out = rePasswordKV.ReplaceAllStringFunc(out, func(m string) string {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=" + redacted
		}
		parts = strings.SplitN(m, ":", 2)
		if len(parts) == 2 {
			return parts[0] + ":" + redacted
		}
		return redacted
	})
	out = strings.ReplaceAll(out, "BEGIN RSA PRIVATE KEY", "BEGIN "+redacted)
	return out
}

func redactMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || lk == "token" || lk == "authorization" {
			out[k] = redacted
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = Redact(t)
		default:
			out[k] = v
		}
	}
	return out
}
