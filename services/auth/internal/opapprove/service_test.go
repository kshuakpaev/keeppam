package opapprove

import (
	"testing"

	"github.com/keeppam/auth/internal/policy"
)

func TestSkipWait(t *testing.T) {
	if !SkipWait(true, nil) {
		t.Fatal("break-glass")
	}
	if SkipWait(false, nil) {
		t.Fatal("normal")
	}
	if !SkipWait(false, &policy.Snapshot{AdminBypass: true}) {
		t.Fatal("admin bypass")
	}
	if !SkipWait(false, &policy.Snapshot{BreakGlass: true}) {
		t.Fatal("snapshot glass")
	}
}

func TestNormalizeChannel(t *testing.T) {
	if NormalizeChannel("SSH") != "ssh" || NormalizeChannel("k8s") != "k8s" || NormalizeChannel("") != "http" {
		t.Fatal(NormalizeChannel("SSH"), NormalizeChannel("k8s"), NormalizeChannel(""))
	}
}

func TestAuditAction(t *testing.T) {
	if auditAction("ssh", "approved") != "session.command.approved" {
		t.Fatal(auditAction("ssh", "approved"))
	}
	if auditAction("http", "approval_required") != "session.app.approval_required" {
		t.Fatal(auditAction("http", "approval_required"))
	}
}
