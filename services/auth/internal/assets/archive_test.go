package assets

import (
	"testing"
)

func TestStatusFilterValues(t *testing.T) {
	if StatusFilterListed != "listed" || StatusFilterArchived != "archived" || StatusFilterAll != "all" {
		t.Fatalf("unexpected filter constants")
	}
}

func TestDeleteErrors(t *testing.T) {
	if ErrNotArchived == nil || ErrActiveSessions == nil {
		t.Fatal("sentinel errors missing")
	}
	if ErrNotArchived.Error() == "" || ErrActiveSessions.Error() == "" {
		t.Fatal("empty error text")
	}
}
