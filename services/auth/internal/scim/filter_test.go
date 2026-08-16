package scim

import "testing"

func TestParseEqFilter(t *testing.T) {
	f, ok := ParseEqFilter(`userName eq "alice"`)
	if !ok || f.Attr != "username" && f.Attr != "userName" {
		if !ok || f.Attr != "username" {
			t.Fatalf("%+v %v", f, ok)
		}
	}
	if f.Value != "alice" {
		t.Fatalf("value %q", f.Value)
	}
	f, ok = ParseEqFilter(`displayName eq "dba-prod"`)
	if !ok || f.Attr != "displayname" || f.Value != "dba-prod" {
		t.Fatalf("%+v", f)
	}
	f, ok = ParseEqFilter(`externalId eq 'abc'`)
	if !ok || f.Attr != "externalid" || f.Value != "abc" {
		t.Fatalf("%+v", f)
	}
	if _, ok := ParseEqFilter(`userName co "a"`); ok {
		t.Fatal("co not supported")
	}
}

func TestClampPage(t *testing.T) {
	off, lim := ClampPage(0, 0)
	if off != 0 || lim != 100 {
		t.Fatalf("%d %d", off, lim)
	}
	off, lim = ClampPage(3, 500)
	if off != 2 || lim != 200 {
		t.Fatalf("%d %d", off, lim)
	}
}
