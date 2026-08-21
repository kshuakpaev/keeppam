package policy

import "testing"

func TestParseSCPExec(t *testing.T) {
	sink, dest, ok := ParseSCPExec("scp -t demo-linux-01")
	if !ok || !sink || dest != "demo-linux-01" {
		t.Fatalf("t: sink=%v dest=%q ok=%v", sink, dest, ok)
	}
	sink, dest, ok = ParseSCPExec("scp -f -- demo-linux-01/tmp")
	if !ok || sink || dest != "demo-linux-01/tmp" {
		t.Fatalf("f: sink=%v dest=%q ok=%v", sink, dest, ok)
	}
	if _, _, ok := ParseSCPExec("ls -la"); ok {
		t.Fatal("ls")
	}
}

func TestNormalizeFileTransfer(t *testing.T) {
	v, err := NormalizeFileTransfer("", true)
	if err != nil || v != "" {
		t.Fatalf("inherit empty: %q %v", v, err)
	}
	v, err = NormalizeFileTransfer("", false)
	if err != nil || v != FileTransferDeny {
		t.Fatalf("policy empty: %q %v", v, err)
	}
	if _, err := NormalizeFileTransfer("drop", false); err == nil {
		t.Fatal("drop")
	}
}
