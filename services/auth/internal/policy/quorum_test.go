package policy

import (
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeApprovalMode(t *testing.T) {
	if NormalizeApprovalMode("") != ApprovalSequential {
		t.Fatal("default sequential")
	}
	if NormalizeApprovalMode("QUORUM") != ApprovalQuorum {
		t.Fatal("quorum")
	}
	if IsQuorumMode("sequential") {
		t.Fatal("sequential is not quorum")
	}
}

func TestNormalizeQuorum(t *testing.T) {
	n, m, err := NormalizeQuorum(2, 3)
	if err != nil || n != 2 || m != 3 {
		t.Fatalf("2/3: %d %d %v", n, m, err)
	}
	n, m, err = NormalizeQuorum(3, 5)
	if err != nil || n != 3 || m != 5 {
		t.Fatalf("3/5: %d %d %v", n, m, err)
	}
	if _, _, err := NormalizeQuorum(0, 3); err == nil {
		t.Fatal("n=0")
	}
	if _, _, err := NormalizeQuorum(4, 3); err == nil {
		t.Fatal("n>m")
	}
	if _, _, err := NormalizeQuorum(1, 17); err == nil {
		t.Fatal("m>16")
	}
}

func TestQuorumReached(t *testing.T) {
	if QuorumReached(1, 2) {
		t.Fatal("1 of 2")
	}
	if !QuorumReached(2, 2) {
		t.Fatal("2 of 2")
	}
	if !QuorumReached(3, 2) {
		t.Fatal("3 of 2")
	}
	if QuorumReached(5, 0) {
		t.Fatal("n=0")
	}
}

func TestAlreadyVoted(t *testing.T) {
	a := uuid.MustParse("01900000-0000-7000-8000-0000000000aa")
	b := uuid.MustParse("01900000-0000-7000-8000-0000000000bb")
	votes := []RequestApproval{{ActorID: a, Stage: StageQuorum}}
	if !AlreadyVoted(votes, a) {
		t.Fatal("a voted")
	}
	if AlreadyVoted(votes, b) {
		t.Fatal("b has not")
	}
	if AlreadyVoted(nil, a) {
		t.Fatal("empty")
	}
}

func TestStagePermissionQuorum(t *testing.T) {
	if StagePermission(StageQuorum) != "access.approve" {
		t.Fatal("quorum uses access.approve")
	}
}
