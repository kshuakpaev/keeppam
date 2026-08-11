package settings

import (
	"crypto/tls"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

type LDAPIdentity struct {
	Username    string
	Email       string
	DisplayName string
}

func (s *Service) AuthenticateLDAP(cfg AuthSettings, bindPasswordEnc []byte, username, password string) (LDAPIdentity, error) {
	if cfg.LDAPURL == "" || cfg.LDAPUserBaseDN == "" {
		return LDAPIdentity{}, fmt.Errorf("ldap is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}
	conn, err := ldap.DialURL(cfg.LDAPURL)
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	if cfg.LDAPStartTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.LDAPInsecureTLS} //nolint:gosec
		if err := conn.StartTLS(tlsCfg); err != nil {
			return LDAPIdentity{}, fmt.Errorf("ldap starttls: %w", err)
		}
	}

	bindPass, err := s.DecryptSecret(bindPasswordEnc)
	if err != nil {
		return LDAPIdentity{}, err
	}
	if cfg.LDAPBindDN != "" {
		if err := conn.Bind(cfg.LDAPBindDN, bindPass); err != nil {
			return LDAPIdentity{}, fmt.Errorf("ldap service bind failed")
		}
	}

	filter := cfg.LDAPUserFilter
	if !strings.Contains(filter, "%s") {
		filter = "(" + cfg.LDAPAttrUsername + "=%s)"
	}
	filter = fmt.Sprintf(filter, ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		cfg.LDAPUserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		[]string{cfg.LDAPAttrUsername, cfg.LDAPAttrEmail, cfg.LDAPAttrDisplayName, "dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) == 0 {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}

	uid := entry.GetAttributeValue(cfg.LDAPAttrUsername)
	if uid == "" {
		uid = username
	}
	email := entry.GetAttributeValue(cfg.LDAPAttrEmail)
	if email == "" {
		email = uid + "@ldap.local"
	}
	dn := entry.GetAttributeValue(cfg.LDAPAttrDisplayName)
	if dn == "" {
		dn = uid
	}
	return LDAPIdentity{Username: uid, Email: email, DisplayName: dn}, nil
}
