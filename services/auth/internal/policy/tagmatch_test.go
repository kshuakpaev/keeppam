package policy

import "testing"

func TestNormalizeMatchMode(t *testing.T) {
	all, err := normalizeMatchMode("")
	if err != nil || all != "all" {
		t.Fatalf("empty: %q %v", all, err)
	}
	any, err := normalizeMatchMode("ANY")
	if err != nil || any != "any" {
		t.Fatalf("any: %q %v", any, err)
	}
	if _, err := normalizeMatchMode("or"); err == nil {
		t.Fatal("or should fail")
	}
}

func TestTagsMatch(t *testing.T) {
	asset := []string{"prod", "linux", "web"}
	if !tagsMatch("all", asset, []string{"prod", "linux"}) {
		t.Fatal("all subset")
	}
	if tagsMatch("all", asset, []string{"prod", "pci"}) {
		t.Fatal("all missing pci")
	}
	if !tagsMatch("any", asset, []string{"pci", "linux"}) {
		t.Fatal("any overlap")
	}
	if tagsMatch("any", asset, []string{"pci", "db"}) {
		t.Fatal("any none")
	}
	if tagsMatch("any", []string{"prod"}, nil) {
		t.Fatal("empty selector")
	}
	if tagsMatch("all", []string{"prod"}, []string{"prod", "linux"}) {
		t.Fatal("all needs every tag")
	}
	if !tagsMatch("all", []string{"prod/linux/web"}, []string{"prod"}) {
		t.Fatal("child implies parent")
	}
	if !tagsMatch("all", []string{"prod/linux/web"}, []string{"prod/linux"}) {
		t.Fatal("child implies mid")
	}
	if tagsMatch("all", []string{"prod"}, []string{"prod/linux"}) {
		t.Fatal("parent does not imply child")
	}
	if !tagsMatch("any", []string{"prod/linux"}, []string{"pci", "prod"}) {
		t.Fatal("any: ancestor of prod")
	}
	if tagsMatch("all", []string{"prod/linux"}, []string{"prod", "linux"}) {
		t.Fatal("path is one tag, not two roots")
	}
}
