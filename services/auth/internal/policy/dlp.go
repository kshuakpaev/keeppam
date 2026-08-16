package policy

import (
	"strings"
)

// FileTransferCommand reports scp/sftp/rsync (including sudo/su wrappers).
func FileTransferCommand(line string) (kind string, ok bool) {
	p := ParseCommand(line)
	switch p.Binary {
	case "scp", "sftp", "rsync":
		return p.Binary, true
	}
	return "", false
}

// SSHChannelDLP denies port-forward / X11 / tun channels.
func SSHChannelDLP(chType string) (reason string, deny bool) {
	switch chType {
	case "session":
		return "", false
	case "direct-tcpip":
		return "", false // allowlist in sshgw via allowed_egress
	case "forwarded-tcpip":
		return "ssh remote port-forward denied by DLP", true
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
