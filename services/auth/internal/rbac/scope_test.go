package rbac

import "testing"

func TestSeesFullAssetCatalog(t *testing.T) {
	if SeesFullAssetCatalog([]string{"assets.read", "sessions.connect", "access.request"}) {
		t.Fatal("operator must not see full catalog")
	}
	if !SeesFullAssetCatalog([]string{"assets.write"}) {
		t.Fatal("inventory admin")
	}
	if !SeesFullAssetCatalog([]string{"assets.acl"}) {
		t.Fatal("acl admin")
	}
	if !SeesFullAssetCatalog([]string{"users.write"}) {
		t.Fatal("platform admin")
	}
	if !SeesFullAssetCatalog([]string{"audit.read"}) {
		t.Fatal("auditor")
	}
}

func TestRestrictToOwnedAssets(t *testing.T) {
	if RestrictToOwnedAssets([]string{"owner"}) != true {
		t.Fatal("owner only")
	}
	if RestrictToOwnedAssets([]string{"owner", "admin"}) {
		t.Fatal("admin sees all")
	}
	if RestrictToOwnedAssets([]string{"operator"}) {
		t.Fatal("operator unrestricted")
	}
	if RestrictToOwnedAssets([]string{"auditor"}) {
		t.Fatal("auditor unrestricted")
	}
}
