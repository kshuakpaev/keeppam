package assets

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/sshkrb"
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
	mode := ""
	if s.sshCA != nil {
		mode = s.sshCA.Mode(ctx)
	}
	useGSSAPI := mode == "gssapi" || creds.AuthMethod == "gssapi"
	if useGSSAPI {
		if s.sshCA == nil {
			return nil, fmt.Errorf("gssapi mode requires ssh settings")
		}
		krbCfg, kt, err := s.sshCA.KerberosConfig(ctx)
		if err != nil {
			return nil, err
		}
		var gss *sshkrb.Client
		if len(kt) > 0 && strings.TrimSpace(krbCfg.Principal) != "" {
			gss, err = sshkrb.NewKeytabClient(krbCfg)
		} else {
			gss, err = sshkrb.NewPasswordClient(krbCfg, creds.Account.Username, creds.Secret)
		}
		if err != nil {
			return nil, err
		}
		target := gssapiTargetHost(creds.Asset)
		cfg.AuthMethod = "gssapi"
		cfg.GSSAPI = gss
		cfg.GSSAPITarget = target
	} else if s.sshCA != nil && mode == "ssh_cert" {
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

func gssapiTargetHost(a Asset) string {
	spn := strings.TrimSpace(a.KrbSPN)
	if spn != "" {
		// accept "host/fqdn" or bare fqdn
		if i := strings.Index(spn, "/"); i >= 0 {
			return strings.ToLower(spn[i+1:])
		}
		return strings.ToLower(spn)
	}
	return sshkrb.HostLabel(a.Hostname, a.Address)
}
