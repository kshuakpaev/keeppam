package policy

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SQLOperation maps a statement to an operation id (empty = read / no extra risk).
func SQLOperation(statement string) string {
	verb, _ := ClassifySQL(statement)
	switch verb {
	case "SELECT":
		return ""
	case "INSERT":
		return "sql.insert"
	case "UPDATE":
		return "sql.update"
	case "DELETE":
		return "sql.delete"
	case "DDL":
		u := strings.ToUpper(statement)
		if strings.Contains(u, "DROP DATABASE") || strings.Contains(u, "DROP SCHEMA") {
			return "sql.drop"
		}
		return "sql.ddl"
	case "EXPORT":
		return "sql.export"
	default:
		if verb == "" {
			return ""
		}
		return "sql.other"
	}
}

// SSHOperation maps a shell line to extra risk (empty = none). File transfer is DLP, not risk.
func SSHOperation(line string) string {
	if _, ok := FileTransferCommand(line); ok {
		return ""
	}
	p := ParseCommand(line)
	if p.PrivShell {
		return "ssh.priv"
	}
	return sshClass(p)
}

func sshClass(p ParsedCommand) string {
	bin := p.Binary
	args := strings.ToLower(strings.Join(p.Args, " "))
	switch bin {
	case "rm", "mkfs", "dd", "shred", "wipefs", "shutdown", "reboot", "halt", "poweroff":
		return "ssh.destructive"
	case "iptables", "nft", "ip6tables", "ebtables", "firewall-cmd":
		return "ssh.firewall"
	case "useradd", "userdel", "usermod", "passwd", "adduser", "deluser", "visudo", "chpasswd":
		return "ssh.user"
	case "chmod":
		if strings.Contains(args, "777") || strings.Contains(args, "0777") || strings.Contains(args, "a+rwx") {
			return "ssh.chmod777"
		}
		return "ssh.chmod"
	case "chown", "chgrp":
		return "ssh.chmod"
	case "journalctl":
		return "ssh.status"
	case "systemctl", "service":
		if len(p.Args) == 0 {
			return "ssh.status"
		}
		sub := strings.ToLower(p.Args[0])
		switch sub {
		case "status", "show", "cat", "list-units", "list-unit-files", "is-active", "is-enabled", "is-failed":
			return "ssh.status"
		case "restart", "start", "stop", "reload", "enable", "disable", "mask", "unmask", "kill", "reset-failed":
			return "ssh.restart"
		default:
			return "ssh.status"
		}
	case "kill", "killall", "pkill":
		return "ssh.restart"
	default:
		return ""
	}
}

// K8sOperation maps a Kubernetes API verb/subresource to extra risk.
func K8sOperation(verb, subresource string) string {
	switch strings.ToLower(strings.TrimSpace(subresource)) {
	case "exec", "attach", "portforward", "proxy":
		return "k8s.exec"
	}
	switch strings.ToLower(strings.TrimSpace(verb)) {
	case "create", "update", "patch":
		return "k8s.write"
	case "delete", "deletecollection":
		return "k8s.delete"
	default:
		return ""
	}
}

// HTTPOperation maps an HTTP method to extra risk (empty = read).
func HTTPOperation(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return ""
	case "DELETE":
		return "http.delete"
	case "POST", "PUT", "PATCH", "TRACE", "CONNECT":
		return "http.write"
	default:
		if strings.TrimSpace(method) == "" {
			return ""
		}
		return "http.write"
	}
}

func operationPoints(op string) (int, string) {
	switch strings.TrimSpace(op) {
	case "sql.insert":
		return 15, "op:sql.insert"
	case "sql.update":
		return 20, "op:sql.update"
	case "sql.delete":
		return 30, "op:sql.delete"
	case "sql.ddl":
		return 45, "op:sql.ddl"
	case "sql.drop":
		return 100, "op:sql.drop"
	case "sql.export":
		return 50, "op:sql.export"
	case "sql.other":
		return 10, "op:sql.other"
	case "k8s.write":
		return 20, "op:k8s.write"
	case "k8s.delete":
		return 35, "op:k8s.delete"
	case "k8s.exec":
		return 45, "op:k8s.exec"
	case "ssh.status":
		return 5, "op:ssh.status"
	case "ssh.restart":
		return 10, "op:ssh.restart"
	case "ssh.priv":
		return 30, "op:ssh.priv"
	case "ssh.chmod":
		return 40, "op:ssh.chmod"
	case "ssh.chmod777":
		return 50, "op:ssh.chmod777"
	case "ssh.user":
		return 60, "op:ssh.user"
	case "ssh.firewall":
		return 70, "op:ssh.firewall"
	case "ssh.destructive":
		return 90, "op:ssh.destructive"
	case "http.write":
		return 20, "op:http.write"
	case "http.delete":
		return 35, "op:http.delete"
	default:
		return 0, ""
	}
}

// CheckOpRisk overlays operation points on the connect-time user score.
// Read operations (0 points) are not re-checked.
// Snapshot (connect freeze) supplies max_risk/risk_action/binding; live Policy edits and ACL revoke do not change in-session ops.
// Without Snapshot (old sessions) a live Evaluate is used. max_risk=0 disables the check.
// Fail-open on lookup errors so an in-session query is not bricked.
func (s *Service) CheckOpRisk(ctx context.Context, in AccessCheck) (AccessResult, error) {
	if in.Bypass {
		return AccessResult{OK: true}, nil
	}
	op := strings.TrimSpace(in.Operation)
	pts, _ := operationPoints(op)
	if pts <= 0 {
		return AccessResult{OK: true}, nil
	}
	var ev AccessResult
	if in.Snapshot != nil {
		ev = in.Snapshot.toResult()
	} else {
		if len(in.RoleNames) == 0 && in.UserID != uuid.Nil {
			names, _ := s.userRoleNames(ctx, in.UserID)
			in.RoleNames = names
		}
		lookup := in
		lookup.SkipRisk = true
		lookup.IgnoreTicket = true
		lookup.Operation = ""
		lookup.Snapshot = nil
		got, err := s.Evaluate(ctx, lookup)
		if err != nil {
			return AccessResult{OK: true}, nil
		}
		ev = got
		if !ev.OK {
			ev = AccessResult{OK: true}
		}
	}
	in.Operation = op
	if ev.MaxRisk > 0 {
		s.applyOpRisk(ctx, in, &ev)
	}
	if ev.OK {
		var tags []string
		if s.db != nil {
			tags, _ = s.UserTags(ctx, in.UserID)
		}
		s.applyOPA(ctx, in, tags, &ev)
	}
	return ev, nil
}

func (s *Service) applyOpRisk(ctx context.Context, in AccessCheck, res *AccessResult) {
	if in.Bypass || res.MaxRisk <= 0 {
		return
	}
	pts, factor := operationPoints(in.Operation)
	if pts <= 0 {
		return
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	inputs, err := s.loadRiskInputs(ctx, in.UserID, in.AssetID, now)
	if err != nil {
		return
	}
	score, factors := computeRisk(inputs)
	score += pts
	if score > 100 {
		score = 100
	}
	factors = append(factors, factor)
	res.RiskScore = score
	res.RiskFactors = factors
	res.Operation = in.Operation
	decideRisk(res, in.StepUpVerified, in.Operation)
	decision := "allow"
	if res.DeniedByRisk {
		decision = res.RiskAction
		if decision == "" {
			decision = "deny"
		}
	}
	payload := map[string]any{
		"score": res.RiskScore, "max_risk": res.MaxRisk, "action": res.RiskAction,
		"factors": res.RiskFactors, "decision": decision, "denied_by_risk": res.DeniedByRisk,
		"operation": in.Operation, "phase": "operation",
	}
	if inputs.UnusualAsset || inputs.SpreadBurst {
		payload["ueba_baseline"] = inputs.UEBABaseline
		payload["ueba_new_asset"] = inputs.UnusualAsset
		payload["ueba_spread"] = inputs.SpreadBurst
	}
	if res.BindingID != nil {
		payload["binding_id"] = res.BindingID.String()
	}
	_ = s.aud.Record(ctx, &in.UserID, "access.risk.evaluated", "asset", in.AssetID.String(), in.ClientIP, "", payload)
}
