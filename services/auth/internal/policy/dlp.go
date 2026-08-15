package policy

import (
	"path"
	"strings"
)

// FileTransferCommand reports scp/sftp/rsync (including sudo wrappers).
func FileTransferCommand(line string) (kind string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return "", false
	}
	i := 0
	switch strings.ToLower(fields[0]) {
	case "sudo", "doas", "pkexec":
		i = skipSudoFlags(fields, 1)
	}
	if i >= len(fields) {
		return "", false
	}
	base := strings.ToLower(path.Base(fields[i]))
	switch base {
	case "scp", "sftp", "rsync":
		return base, true
	}
	return "", false
}

func skipSudoFlags(fields []string, i int) int {
	for i < len(fields) {
		f := fields[i]
		if f == "--" {
			return i + 1
		}
		if !strings.HasPrefix(f, "-") {
			return i
		}
		if strings.Contains(f, "=") {
			i++
			continue
		}
		switch f {
		case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
			"-C", "--close-from", "-D", "--chdir", "-R", "--chroot", "-T", "--command-timeout":
			i += 2
		default:
			i++
		}
	}
	return i
}

// SSHChannelDLP denies port-forward / X11 / tun channels.
func SSHChannelDLP(chType string) (reason string, deny bool) {
	switch chType {
	case "session":
		return "", false
	case "direct-tcpip", "forwarded-tcpip":
		return "ssh port-forward denied by DLP", true
	case "x11":
		return "ssh X11 forwarding denied by DLP", true
	case "tun@openssh.com":
		return "ssh tunnel denied by DLP", true
	default:
		if strings.Contains(strings.ToLower(chType), "tcpip") || strings.HasPrefix(chType, "forwarded-") {
			return "ssh forwarding denied by DLP", true
		}
		return "unknown ssh channel", true
	}
}

func SSHRequestDLP(reqType string) (reason string, deny bool) {
	switch reqType {
	case "tcpip-forward", "cancel-tcpip-forward":
		return "ssh port-forward denied by DLP", true
	case "x11-req":
		return "ssh X11 forwarding denied by DLP", true
	default:
		return "", false
	}
}

func SSHSubsystemDLP(name string) (reason string, deny bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sftp":
		return "sftp subsystem denied by DLP", true
	default:
		return "", false
	}
}

// AllowSSHLine applies DLP file-transfer deny, then optional JEA pack.
func AllowSSHLine(pack CommandPack, hasPack bool, line string) bool {
	if _, ok := FileTransferCommand(line); ok {
		return false
	}
	if hasPack {
		return MatchCommand(pack, line)
	}
	return true
}

// AllowSQL applies DLP export deny, then optional SQL JEA pack.
func AllowSQL(pack SQLPack, hasPack bool, statement string) (bool, string) {
	if denied, reason := ExportDenied(statement); denied {
		return false, reason
	}
	if hasPack {
		return MatchSQL(pack, statement)
	}
	return true, ""
}

// ExportDenied blocks COPY/LOAD/OUTFILE regardless of SQL JEA pack.
func ExportDenied(statement string) (bool, string) {
	s := strings.TrimSpace(reSQLComments.ReplaceAllString(statement, " "))
	if s == "" {
		return false, ""
	}
	u := strings.ToUpper(s)
	if strings.Contains(u, "INTO OUTFILE") || strings.Contains(u, "INTO DUMPFILE") {
		return true, "sql export denied by DLP (OUTFILE)"
	}
	verb, _ := ClassifySQL(statement)
	if verb == "EXPORT" {
		return true, "sql export denied by DLP (COPY/LOAD)"
	}
	return false, ""
}

func SQLRowLimit(pack SQLPack, hasPack bool) int {
	if hasPack && pack.MaxRows > 0 {
		return pack.MaxRows
	}
	return 500
}

func SQLDLPDeny(pack SQLPack, hasPack bool) bool {
	return hasPack && strings.EqualFold(pack.DLPAction, "deny")
}
