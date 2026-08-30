package assets

import "testing"

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`a%b_c\d`); got != `a\%b\_c\\d` {
		t.Fatalf("got %q", got)
	}
}

func TestListFilterWhereListed(t *testing.T) {
	f := ListFilter{Status: StatusFilterListed, Query: "gw"}
	w, args, err := f.where()
	if err != nil {
		t.Fatal(err)
	}
	if w == "" || len(args) != 1 {
		t.Fatalf("where=%q args=%v", w, args)
	}
	if args[0] != "%gw%" {
		t.Fatalf("like %v", args[0])
	}
}

func TestListFilterInvalidStatus(t *testing.T) {
	_, _, err := (ListFilter{Status: "nope"}).where()
	if err == nil {
		t.Fatal("expected error")
	}
}
