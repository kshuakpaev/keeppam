package policy

import "testing"

func TestScanSemanticSalaryAndDrop(t *testing.T) {
	ks := ScanSemantic("compensation review salary")
	found := false
	for _, k := range ks {
		if k == "nlp_sem_salary" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected nlp_sem_salary, got %v", ks)
	}
	out, deny, kinds := ApplyContentDLP(ContentDLP{}, "DROP TABLE employees")
	if deny {
		t.Fatal("semantic must not deny")
	}
	if out != "DROP TABLE employees" {
		t.Fatalf("text changed: %q", out)
	}
	sem := false
	for _, k := range kinds {
		if k == "nlp_sem_schema_drop" {
			sem = true
		}
	}
	if !sem {
		t.Fatalf("expected nlp_sem_schema_drop, kinds=%v", kinds)
	}
}
