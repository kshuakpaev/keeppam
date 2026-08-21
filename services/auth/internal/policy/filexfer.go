package policy

import (
	"fmt"
	"strings"
)

const (
	FileTransferDeny    = "deny"
	FileTransferAudit   = "audit"
	FileTransferCapture = "capture"
)

// NormalizeFileTransfer validates deny|audit|capture.
// inheritEmpty: binding field — empty means inherit from named Policy.
func NormalizeFileTransfer(s string, inheritEmpty bool) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "":
		if inheritEmpty {
			return "", nil
		}
		return FileTransferDeny, nil
	case FileTransferDeny, FileTransferAudit, FileTransferCapture:
		return v, nil
	default:
		return "", fmt.Errorf("file_transfer must be deny, audit, or capture")
	}
}

func EffectiveFileTransfer(mode string) string {
	if mode == "" {
		return FileTransferDeny
	}
	return mode
}

func FileTransferDenied(mode string) bool {
	return EffectiveFileTransfer(mode) == FileTransferDeny
}

func FileTransferStoresBytes(mode string) bool {
	return EffectiveFileTransfer(mode) == FileTransferCapture
}

// ParseSCPExec extracts OpenSSH remote scp -t/-f (legacy SCP). rsync/sftp exec are not SCP.
func ParseSCPExec(line string) (sink bool, dest string, ok bool) {
	p := ParseCommand(line)
	if p.Binary != "scp" {
		return false, "", false
	}
	args := p.Args
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "t") {
				sink = true
			}
			if strings.Contains(a, "f") {
				sink = false
				ok = true
			}
			if strings.Contains(a, "t") {
				ok = true
			}
			continue
		}
		positional = append(positional, a)
	}
	if !ok {
		return false, "", false
	}
	if len(positional) > 0 {
		dest = positional[0]
	}
	if dest == "" {
		dest = "."
	}
	return sink, dest, true
}
