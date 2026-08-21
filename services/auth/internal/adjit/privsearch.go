package adjit

import (
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// PrivAccount is a privileged directory user for discovery (T-09).
type PrivAccount struct {
	Username    string
	DN          string
	DisplayName string
	AdminCount  bool
	MemberOf    []string
	Reasons     []string // adminCount / group CN
}

// SearchPrivileged enumerates users with adminCount=1 and/or membership in known privileged groups.
// extraGroupDNs are additional group DNs to match via memberOf (direct).
func SearchPrivileged(dir DirectoryConfig, extraGroupDNs []string) ([]PrivAccount, error) {
	if strings.TrimSpace(dir.UserBaseDN) == "" {
		return nil, fmt.Errorf("ldap user base dn not configured")
	}
	conn, err := dial(dir)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	groupDNs := append([]string{}, extraGroupDNs...)
	for _, cn := range []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"} {
		if dn, err := findGroupDN(conn, dir.UserBaseDN, cn); err == nil && dn != "" {
			groupDNs = append(groupDNs, dn)
		}
	}
	groupDNs = uniqueDN(groupDNs)

	parts := []string{"(adminCount=1)"}
	for _, g := range groupDNs {
		parts = append(parts, "(memberOf="+ldap.EscapeFilter(g)+")")
		// nested membership (AD)
		parts = append(parts, "(memberOf:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(g)+")")
	}
	filter := "(&(objectCategory=person)(objectClass=user)(|" + strings.Join(parts, "") + "))"

	attrUser := dir.AttrUser
	if attrUser == "" {
		attrUser = "sAMAccountName"
	}
	attrs := []string{"dn", attrUser, "sAMAccountName", "uid", "displayName", "cn", "adminCount", "memberOf"}
	req := ldap.NewSearchRequest(
		dir.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2000, 0, false,
		filter, attrs, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}

	seen := map[string]struct{}{}
	var out []PrivAccount
	for _, e := range res.Entries {
		u := entryToPriv(e, attrUser, groupDNs)
		if u.Username == "" || u.DN == "" {
			continue
		}
		key := strings.ToLower(u.DN)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	return out, nil
}

func findGroupDN(conn *ldap.Conn, base, cn string) (string, error) {
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(cn)),
		[]string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("group not found: %s", cn)
	}
	return res.Entries[0].DN, nil
}

func entryToPriv(e *ldap.Entry, attrUser string, groupDNs []string) PrivAccount {
	u := PrivAccount{DN: e.DN}
	u.Username = firstAttr(e, attrUser, "sAMAccountName", "uid", "cn")
	u.DisplayName = firstAttr(e, "displayName", "cn")
	u.AdminCount = e.GetAttributeValue("adminCount") == "1"
	u.MemberOf = e.GetAttributeValues("memberOf")
	if u.AdminCount {
		u.Reasons = append(u.Reasons, "adminCount=1")
	}
	want := map[string]string{}
	for _, g := range groupDNs {
		want[strings.ToLower(g)] = g
	}
	for _, m := range u.MemberOf {
		if g, ok := want[strings.ToLower(m)]; ok {
			u.Reasons = append(u.Reasons, cnFromDN(g))
		}
	}
	if len(u.Reasons) == 0 && len(u.MemberOf) > 0 {
		u.Reasons = append(u.Reasons, "privileged-group")
	}
	return u
}

func firstAttr(e *ldap.Entry, names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(e.GetAttributeValue(n)); v != "" {
			return v
		}
	}
	return ""
}

func cnFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return dn
	}
	p := strings.TrimSpace(parts[0])
	if strings.HasPrefix(strings.ToUpper(p), "CN=") {
		return p[3:]
	}
	return p
}

func uniqueDN(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		k := strings.ToLower(d)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, d)
	}
	return out
}
