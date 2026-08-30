package sshlegacy

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Enabled is true unless FIPS is required or KEEPPAM_SSH_LEGACY=false.
// Default on: NIT §5 legacy Linux/Unix (group1, ssh-dss, 3DES, ssh-rsa host keys).
func Enabled() bool {
	if boolEnv("KEEPPAM_FIPS_REQUIRED", false) {
		return false
	}
	return boolEnv("KEEPPAM_SSH_LEGACY", true)
}

func boolEnv(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func merge(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := map[string]struct{}{}
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ApplyClient appends insecure KEX/cipher/MAC for old sshd (RHEL 5, Solaris 10)
// without replacing golang.org/x/crypto default preference order.
//
// Do not set HostKeyAlgorithms here. SupportedAlgorithms().HostKeys prefers
// rsa-sha2-256 over ecdsa-sha2-nistp256; OpenSSH (including demo-ssh) then
// presents the RSA host key, which breaks TOFU for assets whose key was
// learned as ECDSA/Ed25519. Library defaults already include ssh-rsa and ssh-dss.
func ApplyClient(cfg *ssh.ClientConfig) {
	if cfg == nil {
		return
	}
	cfg.SetDefaults()
	i := ssh.InsecureAlgorithms()
	cfg.KeyExchanges = merge(cfg.KeyExchanges, i.KeyExchanges)
	cfg.Ciphers = merge(cfg.Ciphers, i.Ciphers)
	cfg.MACs = merge(cfg.MACs, i.MACs)
}

// ApplyServer adds insecure KEX/cipher/MAC so old PuTTY/OpenSSH 4.x can handshake with :2222.
func ApplyServer(cfg *ssh.ServerConfig) {
	if cfg == nil {
		return
	}
	s, i := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	cfg.KeyExchanges = merge(s.KeyExchanges, i.KeyExchanges)
	cfg.Ciphers = merge(s.Ciphers, i.Ciphers)
	cfg.MACs = merge(s.MACs, i.MACs)
	cfg.PublicKeyAuthAlgorithms = merge(s.PublicKeyAuths, i.PublicKeyAuths)
}
