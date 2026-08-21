package adjit

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestEntryToPriv(t *testing.T) {
	e := &ldap.Entry{
		DN: "CN=Alice Admin,CN=Users,DC=corp,DC=local",
		Attributes: []*ldap.EntryAttribute{
			{Name: "sAMAccountName", Values: []string{"alice"}},
			{Name: "displayName", Values: []string{"Alice Admin"}},
			{Name: "adminCount", Values: []string{"1"}},
			{Name: "memberOf", Values: []string{"CN=Domain Admins,CN=Users,DC=corp,DC=local"}},
		},
	}
	u := entryToPriv(e, "sAMAccountName", []string{"CN=Domain Admins,CN=Users,DC=corp,DC=local"})
	if u.Username != "alice" || !u.AdminCount || len(u.Reasons) < 2 {
		t.Fatalf("%+v", u)
	}
}

func TestUniqueDN(t *testing.T) {
	got := uniqueDN([]string{"CN=A", "cn=a", "CN=B", ""})
	if len(got) != 2 {
		t.Fatal(got)
	}
}
