package policy

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

const (
	SSHKindAllow    = "allow"
	SSHKindJEA      = "jea"
	SSHKindDLP      = "dlp"
	SSHKindRisk     = "risk"
	SSHKindApproval = "approval"
)

type SSHLineVerdict struct {
	Allow      bool          `json:"allow"`
	Kind       string        `json:"kind"`
	Parsed     ParsedCommand `json:"parsed"`
	Operation  string        `json:"operation,omitempty"`
	Points     int           `json:"points"`
	RiskScore  int           `json:"risk_score,omitempty"`
	MaxRisk    int           `json:"max_risk,omitempty"`
	RiskAction string        `json:"risk_action,omitempty"`
	PackName   string        `json:"pack,omitempty"`
	Reason     string        `json:"reason,omitempty"`
}

func (v SSHLineVerdict) AuditAction() string {
	switch v.Kind {
	case SSHKindDLP:
		return "session.dlp.denied"
	case SSHKindApproval:
		return "session.command.approval_required"
	case SSHKindRisk:
		return "session.risk.denied"
	case SSHKindLiveDeny:
		return "session.command.live_denied"
	default:
		return "session.command.denied"
	}
}

func (v SSHLineVerdict) EventType() string {
	switch v.Kind {
	case SSHKindDLP:
		return "dlp"
	case SSHKindRisk:
		return "risk"
	case SSHKindApproval:
		return "command_approval"
	default:
		return "command_denied"
	}
}

func (v SSHLineVerdict) Payload(line string) map[string]any {
	p := map[string]any{
		"command": line, "kind": v.Kind, "binary": v.Parsed.Binary,
		"inner": v.Parsed.Inner, "wrappers": v.Parsed.Wrappers,
	}
	if v.Operation != "" {
		p["operation"] = v.Operation
	}
	if v.Points > 0 {
		p["points"] = v.Points
	}
	if v.PackName != "" {
		p["pack"] = v.PackName
	}
	if v.Reason != "" {
		p["reason"] = v.Reason
	}
	if v.Kind == SSHKindApproval {
		p["reason"] = "approval_required"
	}
	if v.RiskScore > 0 {
		p["risk_score"] = v.RiskScore
		p["max_risk"] = v.MaxRisk
		p["risk_action"] = v.RiskAction
	}
	return p
}

func (s *Service) EvaluateSSHLine(ctx context.Context, in AccessCheck, pack CommandPack, hasPack bool, line string) SSHLineVerdict {
	p := ParseCommand(line)
	v := SSHLineVerdict{Parsed: p, PackName: pack.Name}
	if kind, ok := FileTransferCommand(line); ok {
		v.Kind = SSHKindDLP
		v.Operation = kind
		v.Reason = "ssh file transfer denied by DLP"
		return v
	}
	if hasPack && !MatchCommand(pack, line) {
		v.Kind = SSHKindJEA
		v.Reason = "denied by JEA pack"
		return v
	}
	if !sshSessionBypass(in) && snapshotMaxRisk(in) <= 0 {
		for _, op := range SSHOperationsInLine(line) {
			if !IsLiveDeniedOperation(op) {
				continue
			}
			v.Operation = op
			v.Points, _ = operationPoints(op)
			v.Kind = SSHKindLiveDeny
			v.Reason = "live deny: " + op
			return v
		}
	}
	op := SSHOperation(line)
	v.Operation = op
	v.Points, _ = operationPoints(op)
	if op == "" {
		v.Allow = true
		v.Kind = SSHKindAllow
		return v
	}
	in.Operation = op
	ev, err := s.CheckOpRisk(ctx, in)
	if err != nil || ev.OK {
		v.Allow = true
		v.Kind = SSHKindAllow
		v.RiskScore = ev.RiskScore
		v.MaxRisk = ev.MaxRisk
		return v
	}
	v.RiskScore = ev.RiskScore
	v.MaxRisk = ev.MaxRisk
	v.RiskAction = ev.RiskAction
	if ev.RiskAction == "require_approval" {
		v.Kind = SSHKindApproval
		v.Reason = "approval_required"
		return v
	}
	v.Kind = SSHKindRisk
	v.Reason = ev.RiskDenyMessage()
	return v
}

type CommandPreviewInput struct {
	Command string `json:"command"`
	PackID  string `json:"pack_id"`
}

type CommandPreview struct {
	Command    string        `json:"command"`
	Parsed     ParsedCommand `json:"parsed"`
	DLP        bool          `json:"dlp"`
	JEAAllowed *bool         `json:"jea_allowed,omitempty"`
	Pack       string        `json:"pack,omitempty"`
	Operation  string        `json:"operation"`
	Points     int           `json:"points"`
	Kind       string        `json:"kind"`
	Note       string        `json:"note"`
}

func (s *Service) PreviewCommand(ctx context.Context, in CommandPreviewInput) (CommandPreview, error) {
	line := strings.TrimSpace(in.Command)
	out := CommandPreview{
		Command: line,
		Parsed:  ParseCommand(line),
		Note:    "Баллы команды без connect-факторов. APPROVAL/DENY на сессии зависят от max_risk ACL.",
	}
	if kind, ok := FileTransferCommand(line); ok {
		out.DLP = true
		out.Operation = kind
		out.Kind = SSHKindDLP
		out.Note = "DLP: scp/sftp/rsync запрещены всегда"
		return out, nil
	}
	if id := strings.TrimSpace(in.PackID); id != "" {
		pid, err := uuid.Parse(id)
		if err != nil {
			return CommandPreview{}, err
		}
		pack, err := s.GetCommandPack(ctx, pid)
		if err != nil {
			return CommandPreview{}, err
		}
		ok := MatchCommand(pack, line)
		out.JEAAllowed = &ok
		out.Pack = pack.Name
		if !ok {
			out.Kind = SSHKindJEA
			out.Operation = SSHOperation(line)
			out.Points, _ = operationPoints(out.Operation)
			return out, nil
		}
	}
	out.Operation = SSHOperation(line)
	out.Points, _ = operationPoints(out.Operation)
	if out.Parsed.PrivShell {
		out.Kind = "priv_shell"
	} else if out.Operation != "" {
		out.Kind = out.Operation
	} else {
		out.Kind = SSHKindAllow
	}
	return out, nil
}
