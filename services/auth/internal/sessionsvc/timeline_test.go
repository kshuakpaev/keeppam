package sessionsvc

import "testing"

func TestMergeLabels(t *testing.T) {
	got := MergeLabels([]string{"Prod", "pci"}, []string{"pci", " linux "}, nil)
	if len(got) != 3 || got[0] != "linux" || got[1] != "pci" || got[2] != "prod" {
		t.Fatalf("%v", got)
	}
	if len(MergeLabels()) != 0 {
		t.Fatal("empty")
	}
}

func TestAuditSnippet(t *testing.T) {
	if s := AuditSnippet("session.denied", "asset", "x", map[string]any{"reason": "policy"}); s != "session.denied: policy" {
		t.Fatal(s)
	}
	if s := AuditSnippet("asset.acl.granted", "asset", "abc", nil); s != "asset.acl.granted asset abc" {
		t.Fatal(s)
	}
}
