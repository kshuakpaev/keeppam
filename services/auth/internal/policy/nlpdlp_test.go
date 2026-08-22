package policy

import (
	"strings"
	"testing"
)

func TestScanNLPBuiltin(t *testing.T) {
	cfg := NlpDLP{Action: "mask"}
	kinds, masked, deny := scanNLP("Project alpha is CONFIDENTIAL and under NDA", cfg)
	if deny {
		t.Fatal("unexpected deny")
	}
	if len(kinds) == 0 {
		t.Fatal("expected kinds")
	}
	if masked == "Project alpha is CONFIDENTIAL and under NDA" {
		t.Fatalf("expected mask, got %q", masked)
	}
}

func TestScanNLPClassifierMinHits(t *testing.T) {
	cfg := NlpDLP{
		Action: "audit",
		Classifiers: []CompiledNlpClassifier{{
			Name: "trade_secret", Keywords: []string{"alpha", "beta"}, MinHits: 2,
		}},
	}
	kinds, _, deny := scanNLP("alpha release notes only", cfg)
	if len(kinds) != 0 || deny {
		t.Fatalf("expected no hit, got %+v deny=%v", kinds, deny)
	}
	kinds, _, _ = scanNLP("alpha and beta roadmap", cfg)
	if len(kinds) != 1 || kinds[0] != "trade_secret" {
		t.Fatalf("got %+v", kinds)
	}
}

func TestScanNLPPrivateKey(t *testing.T) {
	cfg := NlpDLP{Action: "deny"}
	text := "save this\n-----BEGIN RSA PRIVATE KEY-----\nMIIE"
	kinds, _, deny := scanNLP(text, cfg)
	if !deny || len(kinds) == 0 {
		t.Fatalf("deny=%v kinds=%+v", deny, kinds)
	}
}

func TestApplyContentDLPWithNLP(t *testing.T) {
	c := ContentDLP{
		Action: "mask",
		NLP: NlpDLP{
			Action: "audit",
			Classifiers: []CompiledNlpClassifier{{
				Name: "hr_data", Keywords: []string{"salary"}, MinHits: 1,
			}},
		},
	}
	out, deny, kinds := ApplyContentDLP(c, "user@example.com salary review")
	if deny {
		t.Fatal("deny")
	}
	if len(kinds) < 2 {
		t.Fatalf("expected email+hr kinds, got %+v", kinds)
	}
	if !strings.Contains(out, "***@***") {
		t.Fatalf("pii mask missing: %q", out)
	}
	if !strings.Contains(out, "salary") {
		t.Fatalf("audit should keep nlp keyword: %q", out)
	}
}

func TestNormalizeNlpClassifiers(t *testing.T) {
	got, err := NormalizeNlpClassifiers([]NlpClassifier{{
		Name: "trade_secret", Keywords: "alpha|beta", MinHits: 2,
	}})
	if err != nil || len(got) != 1 {
		t.Fatalf("err=%v got=%+v", err, got)
	}
	if _, err := NormalizeNlpClassifiers([]NlpClassifier{{Name: "nlp_foo", Keywords: "x"}}); err == nil {
		t.Fatal("expected reserved name error")
	}
}
