package assets

import "testing"

func TestUsesDirectoryPassword(t *testing.T) {
	if !usesDirectoryPassword(Asset{ADPrivilegedGroupDN: "CN=G"}, Account{}) {
		t.Fatal("group")
	}
	if !usesDirectoryPassword(Asset{}, Account{ADUserDN: "CN=U"}) {
		t.Fatal("user dn")
	}
	if usesDirectoryPassword(Asset{}, Account{}) {
		t.Fatal("empty")
	}
}
