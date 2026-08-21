package policy

import "testing"

func TestSnapshotRDPDefaultOff(t *testing.T) {
	var sn *Snapshot
	r := sn.RDP()
	if r.Clipboard || r.Drive || r.Printer || r.Native {
		t.Fatalf("nil snapshot must be DLP-strict: %+v", r)
	}
	sn = &Snapshot{RDPClipboard: true, RDPNative: true}
	r = sn.RDP()
	if !r.Clipboard || r.Drive || !r.Native {
		t.Fatalf("unexpected: %+v", r)
	}
}
