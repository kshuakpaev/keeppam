package policy

import "testing"

func TestNormalizeDlpPatterns(t *testing.T) {
	got, err := NormalizeDlpPatterns([]DlpPattern{
		{Name: "passport", Pattern: `\b[A-Z]{2}\d{7}\b`},
	})
	if err != nil || len(got) != 1 || got[0].Name != "passport" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := NormalizeDlpPatterns([]DlpPattern{{Name: "BAD", Pattern: "x"}}); err == nil {
		t.Fatal("expected invalid name")
	}
	if _, err := NormalizeDlpPatterns([]DlpPattern{{Name: "bad", Pattern: "("}}); err == nil {
		t.Fatal("expected invalid regex")
	}
}

func TestApplyContentDLPCustom(t *testing.T) {
	compiled, err := CompileDlpPatterns([]DlpPattern{{Name: "secret", Pattern: `SECRET-\d+`}})
	if err != nil {
		t.Fatal(err)
	}
	c := ContentDLP{Action: "mask", Patterns: compiled}
	out, deny, kinds := ApplyContentDLP(c, "token SECRET-42 ok")
	if deny || len(kinds) != 1 || kinds[0] != "secret" {
		t.Fatalf("deny=%v kinds=%v", deny, kinds)
	}
	if out != "token *** ok" {
		t.Fatalf("got %q", out)
	}
}
