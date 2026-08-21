package policy

import (
	"fmt"
	"strings"
	"testing"
)

func TestParsePatternTXT(t *testing.T) {
	in := "# comment\nrm *\n\ndd\nchmod -R /*\n"
	got, err := ParsePatternList([]byte(in), "deny.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "rm *" {
		t.Fatalf("%v", got)
	}
}

func TestParsePatternJSON(t *testing.T) {
	got, err := ParsePatternList([]byte(`{"patterns":["sudo *","su"]}`), "x.json")
	if err != nil || len(got) != 2 {
		t.Fatal(err, got)
	}
	got, err = ParsePatternList([]byte(`["a","b","a"]`), "x.json")
	if err != nil || len(got) != 2 {
		t.Fatal(err, got)
	}
}

func TestParsePatternCSV(t *testing.T) {
	in := "pattern,note\nrm *,destructive\nmkfs *,disk\n"
	got, err := ParsePatternList([]byte(in), "list.csv")
	if err != nil || len(got) != 2 || got[0] != "rm *" {
		t.Fatal(err, got)
	}
}

func TestParsePatternList500(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "cmd-%d\n", i)
	}
	got, err := ParsePatternList([]byte(b.String()), "big.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 500 {
		t.Fatalf("want 500 got %d", len(got))
	}
}
