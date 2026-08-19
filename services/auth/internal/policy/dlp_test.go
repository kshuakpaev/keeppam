package policy

import "testing"

func TestFileTransferCommand(t *testing.T) {
	cases := map[string]string{
		"scp -t /tmp/x":           "scp",
		"/usr/bin/sftp user@host": "sftp",
		"sudo -u root scp -f .":   "scp",
		"rsync -av ./ dest":       "rsync",
	}
	for line, want := range cases {
		got, ok := FileTransferCommand(line)
		if !ok || got != want {
			t.Fatalf("%q -> %q ok=%v want %s", line, got, ok, want)
		}
	}
	if _, ok := FileTransferCommand("ls -la"); ok {
		t.Fatal("ls")
	}
	if _, ok := FileTransferCommand("sudo ls"); ok {
		t.Fatal("sudo ls")
	}
}

func TestSSHChannelDLP(t *testing.T) {
	if _, deny := SSHChannelDLP("session"); deny {
		t.Fatal("session")
	}
	if _, deny := SSHChannelDLP("direct-tcpip"); deny {
		t.Fatal("direct-tcpip is gated by allowed_egress, not DLP")
	}
	if _, deny := SSHChannelDLP("forwarded-tcpip"); !deny {
		t.Fatal("forwarded-tcpip")
	}
	if _, deny := SSHChannelDLP("x11"); !deny {
		t.Fatal("x11")
	}
	if _, deny := SSHRequestDLP("tcpip-forward"); !deny {
		t.Fatal("tcpip-forward")
	}
	if _, deny := SSHSubsystemDLP("sftp"); !deny {
		t.Fatal("sftp")
	}
}

func TestAllowSSHLineDLP(t *testing.T) {
	pack := CommandPack{Mode: "allowlist", Patterns: []string{"scp *", "ls *"}}
	if AllowSSHLine(pack, true, "scp -t /tmp/x") {
		t.Fatal("scp should be denied by DLP even if pack allows it")
	}
	if !AllowSSHLine(pack, true, "ls -la") {
		t.Fatal("ls")
	}
}

func TestExportDenied(t *testing.T) {
	if ok, _ := ExportDenied("SELECT 1"); ok {
		t.Fatal("select")
	}
	if ok, _ := ExportDenied("COPY tickets TO STDOUT"); !ok {
		t.Fatal("copy")
	}
	if ok, _ := ExportDenied("SELECT * FROM t INTO OUTFILE '/tmp/x'"); !ok {
		t.Fatal("outfile")
	}
	if ok, _ := ExportDenied("LOAD DATA INFILE '/tmp/x' INTO TABLE t"); !ok {
		t.Fatal("load")
	}
	if ok, _ := ExportDenied("BULK INSERT t FROM 'x'"); !ok {
		t.Fatal("bulk")
	}
	if ok, _ := AllowSQL(SQLPack{}, false, "COPY t TO STDOUT"); ok {
		t.Fatal("copy without pack")
	}
	if ok, _ := AllowSQL(SQLPack{Mode: "allowlist", Statements: []string{"SELECT"}, Tables: []string{"t*"}}, true, "SELECT 1"); !ok {
		t.Fatal("select with pack")
	}
}
