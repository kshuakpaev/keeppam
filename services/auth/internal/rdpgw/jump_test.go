package rdpgw

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
)

func TestJumpContainerName(t *testing.T) {
	id := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	got := jumpContainerName(id)
	if got != "kp-rdp-123e4567e89b" {
		t.Fatalf("got %q", got)
	}
}

func TestJumpDrivePath(t *testing.T) {
	id := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	root := "/tmp/recordings"
	p, clip := jumpDrivePath(root, id, &policy.Snapshot{RDPDrive: true, RDPClipboard: true})
	want := filepath.Join(root, "rdp-drive", id.String())
	if p != want || !clip {
		t.Fatalf("drive: path=%q clip=%v want %q", p, clip, want)
	}
	p, clip = jumpDrivePath(root, id, &policy.Snapshot{RDPClipboard: true, FileTransfer: policy.FileTransferCapture})
	want = filepath.Join(root, "rdp-clipboard", id.String())
	if p != want || !clip {
		t.Fatalf("clip staging: path=%q clip=%v want %q", p, clip, want)
	}
	p, clip = jumpDrivePath(root, id, &policy.Snapshot{RDPClipboard: true, FileTransfer: policy.FileTransferDeny})
	if p != "" || !clip {
		t.Fatalf("dlp-strict clip: path=%q clip=%v", p, clip)
	}
}

func TestJumpConfigFromEnvOff(t *testing.T) {
	t.Setenv("KEEPPAM_RDP_JUMP_IMAGE", "off")
	j := JumpConfigFromEnv("/tmp/recordings", "guacd:4822")
	if j.Enabled() {
		t.Fatal("off must disable jump")
	}
}
