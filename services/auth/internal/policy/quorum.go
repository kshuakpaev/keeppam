package policy

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	ApprovalSequential = "sequential"
	ApprovalQuorum     = "quorum"
	StageQuorum        = "quorum"
)

func NormalizeApprovalMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), ApprovalQuorum) {
		return ApprovalQuorum
	}
	return ApprovalSequential
}

func IsQuorumMode(mode string) bool {
	return NormalizeApprovalMode(mode) == ApprovalQuorum
}

// NormalizeQuorum enforces 1 ≤ N ≤ M ≤ 16 (e.g. 2 of 3, 3 of 5).
func NormalizeQuorum(n, m int) (int, int, error) {
	if n < 1 || n > 16 || m < 1 || m > 16 {
		return 0, 0, fmt.Errorf("quorum N and M must be 1..16")
	}
	if n > m {
		return 0, 0, fmt.Errorf("quorum N cannot exceed M")
	}
	return n, m, nil
}

func QuorumReached(votes, n int) bool {
	return n > 0 && votes >= n
}

func AlreadyVoted(approvals []RequestApproval, actorID uuid.UUID) bool {
	for _, a := range approvals {
		if a.ActorID == actorID {
			return true
		}
	}
	return false
}
