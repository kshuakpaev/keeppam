package sshproxy

import "testing"

func TestCommandGuardAllow(t *testing.T) {
	g := NewCommandGuard(func(line string) bool { return line != "rm -rf /" })
	fwd, echo, denied := g.Feed([]byte("ls -l\n"))
	if denied != "" {
		t.Fatalf("denied=%q", denied)
	}
	if string(echo) != "ls -l\r\n" {
		t.Fatalf("echo=%q", echo)
	}
	if string(fwd) != "ls -l\n" {
		t.Fatalf("fwd=%q", fwd)
	}
}

func TestCommandGuardDeny(t *testing.T) {
	g := NewCommandGuard(func(line string) bool { return false })
	fwd, _, denied := g.Feed([]byte("rm -rf /\n"))
	if denied != "rm -rf /" || len(fwd) != 0 {
		t.Fatalf("denied=%q fwd=%q", denied, fwd)
	}
}

func TestCommandGuardNotifyBeforeDecide(t *testing.T) {
	var order []string
	g := NewCommandGuard(func(line string) bool {
		order = append(order, "decide:"+line)
		return true
	})
	g.Notify = func(p []byte) { order = append(order, "notify:"+string(p)) }
	g.Feed([]byte("id\n"))
	if len(order) < 3 || order[0] != "notify:i" || order[1] != "notify:d" || order[2] != "notify:\r\n" || order[3] != "decide:id" {
		t.Fatalf("order=%v", order)
	}
}
