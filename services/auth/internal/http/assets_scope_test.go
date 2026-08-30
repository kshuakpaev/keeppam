package httpapi

import (
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/rbac"
)

func TestApplyAssetEntitlement(t *testing.T) {
	id := uuid.MustParse("01900000-0000-7000-8000-0000000000aa")
	list := []assets.Asset{{
		ID:       id,
		Accounts: []assets.Account{{Username: "root"}},
	}}
	applyAssetEntitlement(list, false, map[uuid.UUID]struct{}{})
	if list[0].Entitled {
		t.Fatal("not entitled")
	}
	if list[0].Accounts != nil {
		t.Fatal("accounts leaked")
	}
	list[0].Accounts = []assets.Account{{Username: "root"}}
	applyAssetEntitlement(list, false, map[uuid.UUID]struct{}{id: {}})
	if !list[0].Entitled || len(list[0].Accounts) != 1 {
		t.Fatal("entitled should keep accounts")
	}
	applyAssetEntitlement(list, true, nil)
	if !list[0].Entitled {
		t.Fatal("admin catalog")
	}
}

func TestSeesFullAssetCatalogMatchesRBAC(t *testing.T) {
	if rbac.SeesFullAssetCatalog([]string{"sessions.connect", "assets.read"}) {
		t.Fatal("operator")
	}
}
