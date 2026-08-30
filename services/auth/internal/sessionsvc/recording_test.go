package sessionsvc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGuacamoleRecording(t *testing.T) {
	if !IsGuacamoleRecording("rdp", "/var/lib/keeppam/recordings/guac/abc") {
		t.Fatal("html5 rdp")
	}
	if IsGuacamoleRecording("rdp", "/var/lib/keeppam/recordings/rdp-native/abc/sess.pcap") {
		t.Fatal("native pcap")
	}
	if IsGuacamoleRecording("rdp", "/data/x.pcap") {
		t.Fatal("pcap ext")
	}
	if !IsGuacamoleRecording("vnc", "/x/guac/id") {
		t.Fatal("vnc")
	}
}

func TestLargestFileInDirSkipsIni(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxy.ini"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sess.pcap"), []byte("pcap-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LargestFileInDir(dir)
	if filepath.Base(got) != "sess.pcap" {
		t.Fatal(got)
	}
}
