package filexfer

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/policy"
)

func TestRdpDirection(t *testing.T) {
	if got := rdpDirection("Download/report.pdf"); got != "download" {
		t.Fatalf("download %q", got)
	}
	if got := rdpDirection("Upload/secret.bin"); got != "upload" {
		t.Fatalf("upload %q", got)
	}
}

func TestIngestRDPDirMissing(t *testing.T) {
	svc := &Service{}
	if err := svc.ingestRDPDir(context.Background(), uuid.New(), t.TempDir()+"/nope", RDPProtocolDrive, true); err != nil {
		t.Fatal(err)
	}
}

func TestIngestRDPSessionSkipsDeny(t *testing.T) {
	root := t.TempDir()
	sess := uuid.New()
	svc := &Service{}
	snap := &policy.Snapshot{FileTransfer: policy.FileTransferDeny, RDPDrive: true}
	if err := svc.IngestRDPSession(context.Background(), sess, root, snap); err != nil {
		t.Fatal(err)
	}
}
