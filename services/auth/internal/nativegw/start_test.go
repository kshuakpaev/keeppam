package nativegw

import "testing"

func TestSplitLogin(t *testing.T) {
	login, hint := SplitLogin("alice+ftp-prod")
	if login != "alice" || hint != "ftp-prod" {
		t.Fatalf("got %q %q", login, hint)
	}
	login, hint = SplitLogin("alice+db1/app")
	if login != "alice" || hint != "db1/app" {
		t.Fatalf("got %q %q", login, hint)
	}
	login, hint = SplitLogin("alice")
	if login != "alice" || hint != "" {
		t.Fatalf("got %q %q", login, hint)
	}
}

func TestResolveTarget(t *testing.T) {
	targets := []targetRef{
		{AssetName: "ora1", AccountName: "system"},
		{AssetName: "ora1", AccountName: "app"},
		{AssetName: "ftp-prod", AccountName: "backup"},
	}
	got, err := resolveTarget(targets, "ftp-prod")
	if err != nil || got.AccountName != "backup" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := resolveTarget(targets, "ora1"); err == nil {
		t.Fatal("expected ambiguous")
	}
	got, err = resolveTarget(targets, "ora1/app")
	if err != nil || got.AccountName != "app" {
		t.Fatalf("%v %+v", err, got)
	}
}
