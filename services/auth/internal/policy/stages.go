package policy

import "strings"

const (
	StageManager  = "manager"
	StageSecurity = "security"
)

func StagePermission(stage string) string {
	if strings.EqualFold(strings.TrimSpace(stage), StageSecurity) {
		return "access.approve.security"
	}
	return "access.approve"
}

// NormalizeApprovalStages keeps manager first, then optional security.
func NormalizeApprovalStages(in []string) []string {
	wantSec := false
	for _, s := range in {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case StageSecurity:
			wantSec = true
		}
	}
	if wantSec {
		return []string{StageManager, StageSecurity}
	}
	return []string{StageManager}
}

func FirstStage(stages []string) string {
	st := NormalizeApprovalStages(stages)
	return st[0]
}

// NextStage returns the following stage after current. ok=false means this was the last.
func NextStage(stages []string, current string) (string, bool) {
	st := NormalizeApprovalStages(stages)
	cur := strings.ToLower(strings.TrimSpace(current))
	if cur == "" {
		cur = StageManager
	}
	for i, s := range st {
		if s == cur && i+1 < len(st) {
			return st[i+1], true
		}
	}
	return "", false
}
