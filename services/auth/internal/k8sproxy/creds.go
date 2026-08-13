package k8sproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keeppam/auth/internal/assets"
)

type Upstream struct {
	Server    *url.URL
	Transport *http.Transport
	Token     string
	HasClientCert bool
}

type kubeConfigFile struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func BuildUpstream(creds assets.TargetCreds) (*Upstream, error) {
	switch creds.AuthMethod {
	case "kubeconfig":
		return fromKubeconfig(creds)
	case "sa_token":
		return fromSAToken(creds)
	default:
		return nil, fmt.Errorf("unsupported k8s auth_method %s", creds.AuthMethod)
	}
}

func fromSAToken(creds assets.TargetCreds) (*Upstream, error) {
	host := strings.TrimSpace(creds.Asset.Address)
	if host == "" {
		return nil, fmt.Errorf("asset address required")
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster address")
	}
	if creds.Asset.Port > 0 && u.Port() == "" {
		u.Host = fmt.Sprintf("%s:%d", u.Hostname(), creds.Asset.Port)
	}
	tok := strings.TrimSpace(creds.Secret)
	if tok == "" {
		return nil, fmt.Errorf("empty sa_token")
	}
	return &Upstream{
		Server: u,
		Token:  tok,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}, nil
}

func fromKubeconfig(creds assets.TargetCreds) (*Upstream, error) {
	var cfg kubeConfigFile
	if err := yaml.Unmarshal([]byte(creds.Secret), &cfg); err != nil {
		return nil, fmt.Errorf("invalid kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 {
		return nil, fmt.Errorf("kubeconfig has no clusters")
	}
	cl := cfg.Clusters[0].Cluster
	server := strings.TrimSpace(cl.Server)
	if addr := strings.TrimSpace(creds.Asset.Address); addr != "" {
		if !strings.Contains(addr, "://") {
			addr = "https://" + addr
		}
		u, err := url.Parse(addr)
		if err == nil {
			if creds.Asset.Port > 0 && u.Port() == "" {
				u.Host = fmt.Sprintf("%s:%d", u.Hostname(), creds.Asset.Port)
			}
			server = u.String()
		}
	}
	if server == "" {
		return nil, fmt.Errorf("kubeconfig cluster.server empty")
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster server")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cl.InsecureSkipTLSVerify || cl.CertificateAuthorityData == "" {
		tlsCfg.InsecureSkipVerify = true
	} else if raw, err := base64.StdEncoding.DecodeString(cl.CertificateAuthorityData); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(raw) || pool.AppendCertsFromPEM(pemWrap(raw)) {
			tlsCfg.RootCAs = pool
		} else if cert, err := x509.ParseCertificate(raw); err == nil {
			pool.AddCert(cert)
			tlsCfg.RootCAs = pool
		} else {
			tlsCfg.InsecureSkipVerify = true
		}
	}
	up := &Upstream{
		Server: u,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	if len(cfg.Users) > 0 {
		usr := cfg.Users[0].User
		up.Token = strings.TrimSpace(usr.Token)
		if usr.ClientCertificateData != "" && usr.ClientKeyData != "" {
			certPEM, err1 := decodePEM(usr.ClientCertificateData)
			keyPEM, err2 := decodePEM(usr.ClientKeyData)
			if err1 == nil && err2 == nil {
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err == nil {
					tlsCfg.Certificates = []tls.Certificate{cert}
					up.HasClientCert = true
				}
			}
		}
	}
	if up.Token == "" && !up.HasClientCert {
		return nil, fmt.Errorf("kubeconfig has neither token nor client cert")
	}
	return up, nil
}

func decodePEM(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "BEGIN") {
		return []byte(v), nil
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(raw), "BEGIN") {
		return raw, nil
	}
	return pemWrap(raw), nil
}

func pemWrap(der []byte) []byte {
	const begin = "-----BEGIN CERTIFICATE-----\n"
	const end = "\n-----END CERTIFICATE-----\n"
	b64 := base64.StdEncoding.EncodeToString(der)
	return []byte(begin + b64 + end)
}

func RenderKubeconfig(server, token string) string {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: %s
  name: keeppam
contexts:
- context:
    cluster: keeppam
    user: keeppam
  name: keeppam
current-context: keeppam
users:
- name: keeppam
  user:
    token: %s
`, server, token)
}
