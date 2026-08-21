package policy

import "testing"

func TestMatchAssetTagAndName(t *testing.T) {
	sel := AssetSelector{Tags: []string{"prod"}, Mode: "all", Name: "prod-*"}
	if !sel.MatchAsset(AssetMeta{Name: "prod-db-01", Tags: []string{"prod"}, Type: "ssh"}) {
		t.Fatal("expected match")
	}
	if sel.MatchAsset(AssetMeta{Name: "dev-db-01", Tags: []string{"prod"}}) {
		t.Fatal("name should fail")
	}
	if sel.MatchAsset(AssetMeta{Name: "prod-db-01", Tags: []string{"dev"}}) {
		t.Fatal("tag should fail")
	}
}

func TestMatchAssetCIDRAndType(t *testing.T) {
	sel := AssetSelector{Types: []string{"rdp"}, CIDRs: []string{"10.1.0.0/16"}}
	if !sel.MatchAsset(AssetMeta{Type: "rdp", Address: "10.1.2.3"}) {
		t.Fatal("expected match")
	}
	if sel.MatchAsset(AssetMeta{Type: "ssh", Address: "10.1.2.3"}) {
		t.Fatal("type")
	}
	if sel.MatchAsset(AssetMeta{Type: "rdp", Address: "10.2.2.3"}) {
		t.Fatal("cidr")
	}
}

func TestMatchGlobHostname(t *testing.T) {
	sel := AssetSelector{Hostname: "*.corp.local"}
	if !sel.MatchAsset(AssetMeta{Hostname: "win01.corp.local"}) {
		t.Fatal("expected host match")
	}
}

func TestSelectorEmpty(t *testing.T) {
	if !(AssetSelector{}).Empty() {
		t.Fatal("empty")
	}
	if (AssetSelector{Name: "x"}).Empty() {
		t.Fatal("not empty")
	}
}
