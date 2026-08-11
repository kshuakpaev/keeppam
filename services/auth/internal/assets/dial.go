package assets

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/sshproxy"
)

// DialSSH opens an outbound SSH connection with TOFU host-key verification.
func (s *Service) DialSSH(ctx context.Context, creds TargetCreds) (*ssh.Client, error) {
	cfg := sshproxy.DialConfig{
		Address:    creds.Asset.Address,
		Port:       creds.Asset.Port,
		Username:   creds.Account.Username,
		AuthMethod: creds.AuthMethod,
		Secret:     creds.Secret,
		HostKey:    append([]byte(nil), creds.Asset.HostKeyBlob...),
	}
	if s.sshCA != nil && s.sshCA.Mode(ctx) == "ssh_cert" {
		signer, err := s.sshCA.SignUser(ctx, creds.Account.Username)
		if err != nil {
			return nil, err
		}
		cfg.AuthMethod = "ssh_cert"
		cfg.Signer = signer
	}
	cfg.OnHostKey = func(algo string, key ssh.PublicKey) error {
		return s.LearnHostKey(ctx, creds.Asset.ID, algo, key.Marshal(), ssh.FingerprintSHA256(key))
	}
	return sshproxy.Dial(cfg)
}
