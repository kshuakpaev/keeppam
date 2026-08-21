package sshkrb

import (
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"golang.org/x/crypto/ssh"
)

// Config is Kerberos client settings for outbound SSH GSSAPI.
type Config struct {
	Realm       string
	Krb5Config  string // contents of krb5.conf
	Principal   string // optional keytab principal
	Keytab      []byte // optional
	SPNTemplate string // default host/%h ; %h = host label
}

// Client implements ssh.GSSAPIClient using gokrb5 (RFC 4462 gssapi-with-mic).
type Client struct {
	krb        *client.Client
	sessionKey types.EncryptionKey
	haveKey    bool
}

// NewPasswordClient logs in as username@realm with password (vault secret).
func NewPasswordClient(cfg Config, username, password string) (*Client, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, fmt.Errorf("gssapi: username and password required")
	}
	realm := strings.ToUpper(strings.TrimSpace(cfg.Realm))
	if realm == "" {
		return nil, fmt.Errorf("gssapi: krb5_realm required")
	}
	krbCfg, err := loadConfig(cfg.Krb5Config, realm)
	if err != nil {
		return nil, err
	}
	cl := client.NewWithPassword(username, realm, password, krbCfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}
	return &Client{krb: cl}, nil
}

// NewKeytabClient authenticates with a keytab (service or user principal).
func NewKeytabClient(cfg Config) (*Client, error) {
	if len(cfg.Keytab) == 0 {
		return nil, fmt.Errorf("gssapi: keytab empty")
	}
	realm := strings.ToUpper(strings.TrimSpace(cfg.Realm))
	if realm == "" {
		return nil, fmt.Errorf("gssapi: krb5_realm required")
	}
	kt := keytab.New()
	if err := kt.Unmarshal(cfg.Keytab); err != nil {
		return nil, fmt.Errorf("parse keytab: %w", err)
	}
	princ := strings.TrimSpace(cfg.Principal)
	if princ == "" {
		return nil, fmt.Errorf("gssapi: krb5_principal required for keytab")
	}
	user, princRealm := splitPrincipal(princ, realm)
	krbCfg, err := loadConfig(cfg.Krb5Config, princRealm)
	if err != nil {
		return nil, err
	}
	cl := client.NewWithKeytab(user, princRealm, kt, krbCfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos keytab login: %w", err)
	}
	return &Client{krb: cl}, nil
}

func loadConfig(raw, realm string) (*config.Config, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return config.NewFromString(raw)
	}
	minimal := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_realm = true
 dns_lookup_kdc = true
 rdns = false
 forwardable = true

[realms]
 %s = {
 }

[domain_realm]
 .%s = %s
 %s = %s
`, realm, realm, strings.ToLower(realm), realm, strings.ToLower(realm), realm)
	return config.NewFromString(minimal)
}

func splitPrincipal(p, defaultRealm string) (user, realm string) {
	p = strings.TrimSpace(p)
	if i := strings.LastIndex(p, "@"); i >= 0 {
		return p[:i], strings.ToUpper(p[i+1:])
	}
	return p, defaultRealm
}

// SPN builds host/fqdn from template and host label.
func SPN(template, host string) string {
	host = strings.TrimSpace(host)
	template = strings.TrimSpace(template)
	if template == "" {
		template = "host/%h"
	}
	if host == "" {
		return strings.ReplaceAll(template, "%h", "localhost")
	}
	return strings.ReplaceAll(template, "%h", host)
}

// HostLabel prefers FQDN hostname, else address.
func HostLabel(hostname, address string) string {
	h := strings.TrimSpace(hostname)
	if h != "" && strings.Contains(h, ".") {
		return strings.ToLower(h)
	}
	a := strings.TrimSpace(address)
	if a != "" {
		return strings.ToLower(a)
	}
	return strings.ToLower(h)
}

func (c *Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	if c == nil || c.krb == nil {
		return nil, false, fmt.Errorf("gssapi client not initialized")
	}
	if len(token) > 0 {
		return nil, false, nil
	}
	spn := strings.Replace(target, "@", "/", 1)
	tkt, key, err := c.krb.GetServiceTicket(spn)
	if err != nil {
		return nil, false, fmt.Errorf("service ticket %s: %w", spn, err)
	}
	c.sessionKey = key
	c.haveKey = true

	gssFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagMutual}
	if isGSSDelegCreds {
		gssFlags = append(gssFlags, gssapi.ContextFlagDeleg, gssapi.ContextFlagConf)
	}
	var apOpts []int
	if isGSSDelegCreds {
		apOpts = append(apOpts, flags.APOptionMutualRequired)
	}
	tok, err := spnego.NewKRB5TokenAPREQ(c.krb, tkt, key, gssFlags, apOpts)
	if err != nil {
		return nil, false, err
	}
	b, err := tok.Marshal()
	if err != nil {
		return nil, false, err
	}
	return b, false, nil
}

func (c *Client) GetMIC(micField []byte) ([]byte, error) {
	if !c.haveKey {
		return nil, fmt.Errorf("gssapi: no session key")
	}
	token, err := gssapi.NewInitiatorMICToken(micField, c.sessionKey)
	if err != nil {
		return nil, err
	}
	return token.Marshal()
}

func (c *Client) DeleteSecContext() error {
	c.haveKey = false
	c.sessionKey = types.EncryptionKey{}
	if c.krb != nil {
		c.krb.Destroy()
		c.krb = nil
	}
	return nil
}

var _ ssh.GSSAPIClient = (*Client)(nil)
