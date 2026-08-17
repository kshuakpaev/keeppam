package policy

import "strings"

// Live-deny blocks high-impact SSH ops in PTY even when max_risk=0 and no JEA pack.
var liveDenyOps = map[string]struct{}{
	"ssh.destructive": {},
	"ssh.firewall":    {},
	"ssh.user":        {},
	"ssh.chmod777":    {},
}

const SSHKindLiveDeny = "live_deny"

func IsLiveDeniedOperation(op string) bool {
	_, ok := liveDenyOps[strings.TrimSpace(op)]
	return ok
}

func sshSessionBypass(in AccessCheck) bool {
	if in.Bypass {
		return true
	}
	if in.Snapshot != nil && (in.Snapshot.BreakGlass || in.Snapshot.AdminBypass) {
		return true
	}
	return false
}

func snapshotMaxRisk(in AccessCheck) int {
	if in.Snapshot == nil {
		return 0
	}
	return in.Snapshot.MaxRisk
}

// SSHOperationsInLine returns classified ops for a shell line (pipes / chains, not full AST).
func SSHOperationsInLine(line string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, seg := range splitShellSegments(line) {
		op := SSHOperation(seg)
		if op == "" {
			continue
		}
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		out = append(out, op)
	}
	return out
}

func splitShellSegments(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	var segs []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '|' || c == ';' {
			if s := strings.TrimSpace(b.String()); s != "" {
				segs = append(segs, s)
			}
			b.Reset()
			continue
		}
		if c == '&' && i+1 < len(line) && line[i+1] == '&' {
			if s := strings.TrimSpace(b.String()); s != "" {
				segs = append(segs, s)
			}
			b.Reset()
			i++
			continue
		}
		b.WriteByte(c)
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		segs = append(segs, s)
	}
	if len(segs) == 0 {
		return []string{line}
	}
	return segs
}
