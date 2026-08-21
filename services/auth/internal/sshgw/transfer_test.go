package sshgw

import "testing"

func TestSplitSSHLogin(t *testing.T) {
	u, h := splitSSHLogin("alice+demo-linux-01")
	if u != "alice" || h != "demo-linux-01" {
		t.Fatalf("%s %s", u, h)
	}
	u, h = splitSSHLogin("alice")
	if u != "alice" || h != "" {
		t.Fatalf("plain %s %s", u, h)
	}
}

func TestResolveTransferDest(t *testing.T) {
	targets := []targetRef{
		{AssetName: "demo-linux-01", AccountName: "root", Label: "demo-linux-01/root"},
	}
	tr, path, err := resolveTransferDest(targets, "demo-linux-01", "")
	if err != nil || tr.AssetName != "demo-linux-01" || path != "." {
		t.Fatalf("%v %v %s", tr, err, path)
	}
	tr, path, err = resolveTransferDest(targets, "demo-linux-01/var/tmp", "")
	if err != nil || path != "var/tmp" {
		t.Fatalf("sub %s %v", path, err)
	}
	tr, path, err = resolveTransferDest(targets, ".", "demo-linux-01")
	if err != nil || tr.AssetName != "demo-linux-01" {
		t.Fatalf("hint %v %v", err, tr)
	}
}
