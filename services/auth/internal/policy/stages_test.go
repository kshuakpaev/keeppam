package policy

import "testing"

func TestNormalizeApprovalStages(t *testing.T) {
	if got := NormalizeApprovalStages(nil); len(got) != 1 || got[0] != StageManager {
		t.Fatalf("%v", got)
	}
	if got := NormalizeApprovalStages([]string{"security"}); len(got) != 2 || got[1] != StageSecurity {
		t.Fatalf("security-only became %v", got)
	}
	if got := NormalizeApprovalStages([]string{"manager", "security", "security"}); len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if got := NormalizeApprovalStages([]string{"dba", "owner"}); got[0] != StageManager || len(got) != 1 {
		t.Fatalf("unknown stages %v", got)
	}
}

func TestNextStage(t *testing.T) {
	two := []string{StageManager, StageSecurity}
	n, ok := NextStage(two, StageManager)
	if !ok || n != StageSecurity {
		t.Fatal("manager -> security")
	}
	if _, ok := NextStage(two, StageSecurity); ok {
		t.Fatal("security is last")
	}
	if _, ok := NextStage(nil, StageManager); ok {
		t.Fatal("single stage")
	}
}

func TestStagePermission(t *testing.T) {
	if StagePermission(StageSecurity) != "access.approve.security" {
		t.Fatal("security perm")
	}
	if StagePermission("") != "access.approve" {
		t.Fatal("default manager")
	}
}
