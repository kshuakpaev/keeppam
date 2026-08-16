package policy

import "testing"

func TestParseCommandSudo(t *testing.T) {
	p := ParseCommand("sudo -u root ls -la /tmp")
	if p.Binary != "ls" || p.Inner != "ls -la /tmp" {
		t.Fatalf("%+v", p)
	}
	if len(p.Wrappers) != 1 || p.Wrappers[0] != "sudo" {
		t.Fatalf("wrappers %v", p.Wrappers)
	}
}

func TestParseCommandSuC(t *testing.T) {
	p := ParseCommand(`su -c 'rm -rf /var/tmp/x'`)
	if p.Binary != "rm" || !contains(p.Args, "-rf") {
		t.Fatalf("%+v", p)
	}
}

func TestParseCommandPrivShell(t *testing.T) {
	if !ParseCommand("sudo -i").PrivShell {
		t.Fatal("sudo -i")
	}
	if !ParseCommand("su -").PrivShell {
		t.Fatal("su -")
	}
	if ParseCommand("sudo ls").PrivShell {
		t.Fatal("sudo ls not priv shell")
	}
}

func TestParseCommandEnvNoHup(t *testing.T) {
	p := ParseCommand("FOO=bar nohup /usr/bin/useradd alice")
	if p.Binary != "useradd" {
		t.Fatalf("%+v", p)
	}
}

func TestMatchCommandUnwrapsSudo(t *testing.T) {
	pack := CommandPack{Mode: "allowlist", Patterns: []string{"ls", "ls *", "cat *"}}
	if !MatchCommand(pack, "sudo ls -la") {
		t.Fatal("sudo ls should match ls")
	}
	if MatchCommand(pack, "sudo rm -rf /") {
		t.Fatal("sudo rm should not match")
	}
}

func TestFileTransferSudoScp(t *testing.T) {
	kind, ok := FileTransferCommand("sudo scp -t /tmp")
	if !ok || kind != "scp" {
		t.Fatalf("%s %v", kind, ok)
	}
}

func TestPreviewCommandNoPack(t *testing.T) {
	s := &Service{}
	out, err := s.PreviewCommand(nil, CommandPreviewInput{Command: "sudo rm -rf /tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Parsed.Binary != "rm" || out.Operation != "ssh.destructive" || out.Points != 90 {
		t.Fatalf("%+v", out)
	}
	if out.DLP {
		t.Fatal("not dlp")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
