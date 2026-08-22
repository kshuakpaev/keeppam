package assets

import "testing"

func TestNormalizeSyncOrder(t *testing.T) {
	o, err := normalizeSyncOrder("")
	if err != nil || o != SyncOrderDirectoryLast {
		t.Fatalf("default: %q %v", o, err)
	}
	o, err = normalizeSyncOrder("directory_first")
	if err != nil || o != SyncOrderDirectoryFirst {
		t.Fatalf("first: %q %v", o, err)
	}
	if _, err := normalizeSyncOrder("bogus"); err == nil {
		t.Fatal("expected error")
	}
}

func TestOracleQuotes(t *testing.T) {
	if got := oracleQuoteIdent(`scott"`); got != `"scott"""` {
		t.Fatalf("ident %q", got)
	}
	if got := oracleQuoteLiteral(`a"b`); got != `"a""b"` {
		t.Fatalf("lit %q", got)
	}
}

func TestOracleServiceName(t *testing.T) {
	if got := oracleServiceName(Asset{}); got != "ORCL" {
		t.Fatalf("default %q", got)
	}
	if got := oracleServiceName(Asset{DatabaseName: " XEPDB1 "}); got != "XEPDB1" {
		t.Fatalf("custom %q", got)
	}
}

func TestMSSQLQuotes(t *testing.T) {
	if got := mssqlQuoteIdent("sa]"); got != "[sa]]]" {
		t.Fatalf("ident %q", got)
	}
	if got := mssqlQuoteLiteral("a'b"); got != "N'a''b'" {
		t.Fatalf("lit %q", got)
	}
}

func TestOrderedMembers(t *testing.T) {
	s := &Service{}
	set := PasswordSet{
		SyncOrder: SyncOrderDirectoryLast,
		Members: []PasswordSetMember{
			{Username: "ad", Directory: true},
			{Username: "unix", Directory: false},
		},
	}
	ord, err := s.orderedPasswordSetMembers(nil, set)
	if err != nil {
		t.Fatal(err)
	}
	if ord[0].Username != "unix" || ord[1].Username != "ad" {
		t.Fatalf("order last: %+v", ord)
	}
	set.SyncOrder = SyncOrderDirectoryFirst
	ord, err = s.orderedPasswordSetMembers(nil, set)
	if err != nil {
		t.Fatal(err)
	}
	if ord[0].Username != "ad" || ord[1].Username != "unix" {
		t.Fatalf("order first: %+v", ord)
	}
}
