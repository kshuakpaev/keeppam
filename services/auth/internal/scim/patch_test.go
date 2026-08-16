package scim

import "testing"

func TestClassifyGroupPatchAddRemove(t *testing.T) {
	replace, add, remove, display, err := classifyGroupPatch([]PatchOperation{
		{Op: "Add", Path: "members", Value: []any{map[string]any{"value": "u1"}}},
		{Op: "Remove", Path: `members[value eq "u2"]`},
		{Op: "Replace", Path: "displayName", Value: "dba"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if replace != nil {
		t.Fatalf("replace %+v", replace)
	}
	if len(add) != 1 || add[0].Value != "u1" {
		t.Fatalf("add %+v", add)
	}
	if len(remove) != 1 || remove[0].Value != "u2" {
		t.Fatalf("remove %+v", remove)
	}
	if display != "dba" {
		t.Fatalf("display %q", display)
	}
}

func TestClassifyGroupPatchReplaceMembersEmpty(t *testing.T) {
	replace, _, _, _, err := classifyGroupPatch([]PatchOperation{
		{Op: "replace", Path: "members", Value: []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if replace == nil || len(replace) != 0 {
		t.Fatalf("want empty replace, got %#v", replace)
	}
}

func TestAsMembersEmptySlice(t *testing.T) {
	got := asMembers([]any{})
	if got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
}
