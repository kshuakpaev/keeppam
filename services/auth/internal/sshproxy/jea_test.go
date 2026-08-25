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

func TestCommandGuardArrowKeysNotEchoedAsGarbage(t *testing.T) {
	g := NewCommandGuard(func(line string) bool { return true })
	// Type "ab", then left, left, then Enter — must not leave "[D" in the line.
	fwd, echo, denied := g.Feed([]byte("ab\x1b[D\x1b[D\n"))
	if denied != "" {
		t.Fatalf("denied=%q", denied)
	}
	if string(fwd) != "ab\n" {
		t.Fatalf("fwd=%q", fwd)
	}
	if stringsContains(echo, '[') && stringsContains(echo, 'D') && !hasESC(echo) {
		// bare [D without ESC would be the old bug
		t.Fatalf("echo leaked raw [D: %q", echo)
	}
	// After two lefts, cursor at start; echo should include CSI left moves.
	if !hasESC(echo) {
		t.Fatalf("expected CSI echo for cursor moves, got %q", echo)
	}
}

func TestCommandGuardArrowInsertMiddle(t *testing.T) {
	g := NewCommandGuard(func(line string) bool { return true })
	// "ac", left, "b" → "abc"
	fwd, _, denied := g.Feed([]byte("ac\x1b[Db\n"))
	if denied != "" {
		t.Fatalf("denied=%q", denied)
	}
	if string(fwd) != "abc\n" {
		t.Fatalf("fwd=%q want abc\\n", fwd)
	}
}

func TestCommandGuardSS3Cursor(t *testing.T) {
	g := NewCommandGuard(func(line string) bool { return true })
	fwd, _, _ := g.Feed([]byte("xy\x1bOD\x1bOD\n"))
	if string(fwd) != "xy\n" {
		t.Fatalf("fwd=%q", fwd)
	}
}

func hasESC(p []byte) bool {
	for _, b := range p {
		if b == 0x1b {
			return true
		}
	}
	return false
}

func stringsContains(p []byte, c byte) bool {
	for _, b := range p {
		if b == c {
			return true
		}
	}
	return false
}
