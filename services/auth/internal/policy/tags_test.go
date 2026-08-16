package policy

import "testing"

func TestTagsCoverAND(t *testing.T) {
	have := toSet([]string{"prod", "pci", "linux"})
	if !hasAll(have, []string{"prod", "pci"}) {
		t.Fatal("AND both tags")
	}
	if hasAll(have, []string{"prod", "windows"}) {
		t.Fatal("missing windows")
	}
	if hasAll(toSet(nil), []string{"prod"}) {
		t.Fatal("empty asset")
	}
	if !hasAll(have, nil) {
		t.Fatal("empty need")
	}
}

func TestNormalizeTagsSorted(t *testing.T) {
	got := normalizeTags([]string{"PCI", "prod", "pci", " Linux "})
	if len(got) != 3 || got[0] != "linux" || got[1] != "pci" || got[2] != "prod" {
		t.Fatalf("%v", got)
	}
}
