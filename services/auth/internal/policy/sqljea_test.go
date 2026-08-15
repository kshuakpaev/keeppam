package policy

import "testing"

func TestMatchSQLAllowlist(t *testing.T) {
	pack := SQLPack{
		Mode:       "allowlist",
		Statements: []string{"SELECT"},
		Tables:     []string{"tickets", "tickets*"},
	}
	ok, _ := MatchSQL(pack, "SELECT * FROM tickets")
	if !ok {
		t.Fatal("expected allow SELECT tickets")
	}
	ok, reason := MatchSQL(pack, "DELETE FROM tickets")
	if ok {
		t.Fatalf("expected deny DELETE, got ok reason=%s", reason)
	}
	ok, _ = MatchSQL(pack, "SELECT 1")
	if !ok {
		t.Fatal("expected allow SELECT without table")
	}
}

func TestClassifySQLExport(t *testing.T) {
	verb, _ := ClassifySQL("COPY tickets TO STDOUT")
	if verb != "EXPORT" {
		t.Fatalf("COPY verb=%s", verb)
	}
	verb, _ = ClassifySQL("LOAD DATA INFILE '/tmp/x' INTO TABLE t")
	if verb != "EXPORT" {
		t.Fatalf("LOAD verb=%s", verb)
	}
}

func TestMaskSQLResult(t *testing.T) {
	pack := SQLPack{MaskColumns: []string{"amount"}, MaskReplacement: "***"}
	cols, rows := MaskSQLResult(pack, []string{"id", "amount"}, [][]string{{"1", "1200"}})
	if cols[1] != "amount" || rows[0][1] != "***" {
		t.Fatalf("mask failed: %#v %#v", cols, rows)
	}
}
