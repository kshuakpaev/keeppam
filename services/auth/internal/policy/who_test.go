package policy

import (
	"testing"

	"github.com/google/uuid"
)

func TestMatchWHO(t *testing.T) {
	u := uuid.MustParse("01900000-0000-7000-8000-000000000001")
	g := uuid.MustParse("01900000-0000-7000-8000-000000000090")
	r := uuid.MustParse("01900000-0000-7000-8000-000000000002")
	role := "operator"
	if !matchWHO(u, &u, nil, nil, nil, nil, nil) {
		t.Fatal("user")
	}
	if !matchWHO(u, nil, &r, nil, &role, map[string]struct{}{"operator": {}}, nil) {
		t.Fatal("role")
	}
	if !matchWHO(u, nil, nil, &g, nil, nil, map[uuid.UUID]struct{}{g: {}}) {
		t.Fatal("group")
	}
	if matchWHO(u, nil, nil, &g, nil, nil, map[uuid.UUID]struct{}{}) {
		t.Fatal("not a member")
	}
}
