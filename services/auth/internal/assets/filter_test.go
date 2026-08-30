package assets

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestListFilterIDRestrictEmpty(t *testing.T) {
	f := ListFilter{Status: StatusFilterListed, IDRestrict: true}
	where, args, err := f.where()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "FALSE") {
		t.Fatalf("want FALSE, got %s", where)
	}
	if len(args) != 0 {
		t.Fatalf("args %v", args)
	}
}

func TestListFilterIDRestrictAny(t *testing.T) {
	id := uuid.MustParse("01900000-0000-7000-8000-0000000000aa")
	f := ListFilter{Status: StatusFilterListed, IDRestrict: true, IDs: []uuid.UUID{id}}
	where, args, err := f.where()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "a.id = ANY") {
		t.Fatalf("want ANY, got %s", where)
	}
	if len(args) != 1 {
		t.Fatalf("args %v", args)
	}
}
