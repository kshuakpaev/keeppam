package users

import (
	"testing"

	"github.com/google/uuid"
)

func TestNestingOK(t *testing.T) {
	a := uuid.New()
	b := uuid.New()
	c := uuid.New()
	parentOf := map[uuid.UUID]*uuid.UUID{b: &a}
	if err := nestingOK(c, &b, parentOf, 0); err != nil {
		t.Fatalf("c under b: %v", err)
	}
	if err := nestingOK(a, &a, parentOf, 0); err == nil {
		t.Fatal("self")
	}
	if err := nestingOK(a, &b, parentOf, 0); err == nil {
		t.Fatal("cycle a→b when b→a")
	}
}

func TestNestingDepth(t *testing.T) {
	chain := make([]uuid.UUID, 8)
	parentOf := map[uuid.UUID]*uuid.UUID{}
	for i := range chain {
		chain[i] = uuid.New()
	}
	for i := 1; i < len(chain); i++ {
		p := chain[i-1]
		parentOf[chain[i]] = &p
	}
	leaf := uuid.New()
	parent := chain[len(chain)-1]
	if err := nestingOK(leaf, &parent, parentOf, 0); err == nil {
		t.Fatal("9th level should fail")
	}
	okParent := chain[len(chain)-2]
	if err := nestingOK(leaf, &okParent, parentOf, 0); err != nil {
		t.Fatalf("8th level: %v", err)
	}
}

func TestExpandGroupAncestors(t *testing.T) {
	root := uuid.New()
	mid := uuid.New()
	leaf := uuid.New()
	other := uuid.New()
	parentOf := map[uuid.UUID]*uuid.UUID{mid: &root, leaf: &mid}
	got := expandGroupAncestors([]uuid.UUID{leaf, other}, parentOf)
	if len(got) != 4 {
		t.Fatalf("len %d %+v", len(got), got)
	}
	for _, id := range []uuid.UUID{leaf, mid, root, other} {
		if _, ok := got[id]; !ok {
			t.Fatalf("missing %s", id)
		}
	}
}
