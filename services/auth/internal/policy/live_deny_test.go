package policy

import "testing"

func TestSSHOperationsInLinePipe(t *testing.T) {
	ops := SSHOperationsInLine("echo ok | rm -rf /tmp/x")
	if len(ops) != 1 || ops[0] != "ssh.destructive" {
		t.Fatalf("%v", ops)
	}
}

func TestSSHOperationsInLineChain(t *testing.T) {
	ops := SSHOperationsInLine("ls && useradd alice")
	if len(ops) != 1 || ops[0] != "ssh.user" {
		t.Fatalf("%v", ops)
	}
}

func TestParseCommandBashC(t *testing.T) {
	p := ParseCommand(`bash -c 'rm -rf /var/tmp/x'`)
	if p.Binary != "rm" {
		t.Fatalf("%+v", p)
	}
}

func TestEvaluateSSHLineLiveDeny(t *testing.T) {
	s := &Service{}
	v := s.EvaluateSSHLine(nil, AccessCheck{}, CommandPack{}, false, "rm -rf /tmp/x")
	if v.Allow || v.Kind != SSHKindLiveDeny {
		t.Fatalf("%+v", v)
	}
}

func TestEvaluateSSHLineLiveDenyBypass(t *testing.T) {
	s := &Service{}
	v := s.EvaluateSSHLine(nil, AccessCheck{Bypass: true}, CommandPack{}, false, "rm -rf /tmp/x")
	if !v.Allow {
		t.Fatalf("%+v", v)
	}
}

func TestLiveDenyOnlyWhenMaxRiskZero(t *testing.T) {
	if snapshotMaxRisk(AccessCheck{Snapshot: &Snapshot{MaxRisk: 50}}) <= 0 {
		t.Fatal("expected max risk")
	}
	in := AccessCheck{Snapshot: &Snapshot{MaxRisk: 50}}
	if !sshSessionBypass(in) && snapshotMaxRisk(in) <= 0 {
		t.Fatal("live deny should not run")
	}
}

func TestEvaluateSSHLinePipeLiveDeny(t *testing.T) {
	s := &Service{}
	v := s.EvaluateSSHLine(nil, AccessCheck{}, CommandPack{}, false, "echo x | iptables -F")
	if v.Kind != SSHKindLiveDeny || v.Operation != "ssh.firewall" {
		t.Fatalf("%+v", v)
	}
}
