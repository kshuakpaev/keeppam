package sessionsvc

import (
	"errors"
	"testing"
)

func TestSessionIsWaitingSupervisor(t *testing.T) {
	s := Session{RequireSupervisor: true, Status: "pending"}
	if !s.IsWaitingSupervisor() {
		t.Fatal("pending + required")
	}
	now := s.CreatedAt
	s.SupervisorApprovedAt = &now
	if s.IsWaitingSupervisor() {
		t.Fatal("already approved")
	}
	s.SupervisorApprovedAt = nil
	s.Status = "active"
	if s.IsWaitingSupervisor() {
		t.Fatal("active")
	}
	s.Status = "pending"
	s.RequireSupervisor = false
	if s.IsWaitingSupervisor() {
		t.Fatal("not required")
	}
}

func TestIsWaitingSupervisorError(t *testing.T) {
	if !IsWaitingSupervisor(ErrWaitingSupervisor) {
		t.Fatal("direct")
	}
	if !IsWaitingSupervisor(errors.Join(ErrWaitingSupervisor, errors.New("ws"))) {
		t.Fatal("wrapped")
	}
	if IsWaitingSupervisor(errors.New("nope")) {
		t.Fatal("other")
	}
}
