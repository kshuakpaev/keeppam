package device

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func Normalize(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range in {
		c := canon(raw)
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

func Validate(in []string) ([]string, error) {
	out := Normalize(in)
	for _, c := range out {
		switch c {
		case "TLS", "WEBAUTHN", "SSH":
			continue
		}
		if strings.HasPrefix(c, "SHA256:") && len(c) > 8 {
			continue
		}
		if strings.HasPrefix(c, "sha256:") && len(c) == 7+64 && isHex(c[7:]) {
			continue
		}
		return nil, fmt.Errorf("invalid device %q (use TLS, WEBAUTHN, SSH, sha256:<64 hex> or SHA256:<base64>)", c)
	}
	return out, nil
}

func Allowed(allowed, got []string) bool {
	allowed = Normalize(allowed)
	if len(allowed) == 0 {
		return true
	}
	got = Normalize(got)
	if len(got) == 0 {
		return false
	}
	set := map[string]struct{}{}
	for _, g := range got {
		set[g] = struct{}{}
	}
	for _, a := range allowed {
		if _, ok := set[a]; ok {
			return true
		}
	}
	return false
}

func FromTLS(cs *tls.ConnectionState) []string {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	return []string{"TLS", "sha256:" + hex.EncodeToString(sum[:])}
}

func FromSSHKey(key ssh.PublicKey) []string {
	if key == nil {
		return nil
	}
	return []string{"SSH", ssh.FingerprintSHA256(key)}
}

func Merge(parts ...[]string) []string {
	var all []string
	for _, p := range parts {
		all = append(all, p...)
	}
	return Normalize(all)
}

func canon(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u := strings.ToUpper(s)
	switch u {
	case "TLS", "WEBAUTHN", "SSH":
		return u
	}
	if strings.HasPrefix(u, "SHA256:") {
		return "SHA256:" + strings.TrimSpace(s[7:])
	}
	hexPart := strings.ToLower(strings.ReplaceAll(s, ":", ""))
	hexPart = strings.TrimPrefix(hexPart, "sha256")
	if len(hexPart) == 64 && isHex(hexPart) {
		return "sha256:" + hexPart
	}
	return u
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
