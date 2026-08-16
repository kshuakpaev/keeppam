package tagpath

import "testing"

func TestCanonical(t *testing.T) {
	if got := Canonical(" Prod//Linux/ "); got != "prod/linux" {
		t.Fatalf("got %q", got)
	}
	if Canonical("a/../b") != "" {
		t.Fatal(".. must drop")
	}
	if Canonical("a/b/c/d/e/f/g/h/i") != "" {
		t.Fatal("too deep")
	}
}

func TestExpandAncestors(t *testing.T) {
	got := ExpandAncestors([]string{"prod/linux/web", "pci"})
	want := []string{"pci", "prod", "prod/linux", "prod/linux/web"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}
