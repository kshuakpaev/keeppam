package policy

import (
	"context"
	"path"
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
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}
	i := 0
	switch strings.ToLower(fields[0]) {
	case "sudo", "doas", "pkexec":
		i = skipSudoFlags(fields, 1)
	}
	if i >= len(fields) {
		return "ssh.priv"
	}
	base := strings.ToLower(path.Base(fields[i]))
	switch base {
	case "rm", "mkfs", "dd", "shred", "wipefs",
		"useradd", "userdel", "usermod", "passwd",
		"iptables", "nft", "shutdown", "reboot", "halt", "poweroff",
		"chmod", "chown", "visudo":
		return "ssh.destructive"
	case "sudo", "su", "doas", "pkexec":
		return "ssh.priv"
	}
	return ""
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
	case "ssh.destructive":
		return 40, "op:ssh.destructive"
	case "ssh.priv":
		return 25, "op:ssh.priv"
	case "http.write":
		return 20, "op:http.write"
	case "http.delete":
		return 35, "op:http.delete"
	default:
		return 0, ""
	}
}

// CheckOpRisk overlays operation points on the connect-time user score.
// Read operations (0 points) are not re-checked. JIT windows still apply (unlike connect).
// max_risk=0 disables this check. Fail-open on lookup errors so an in-session query is not bricked.
func (s *Service) CheckOpRisk(ctx context.Context, in AccessCheck) (AccessResult, error) {
	if in.Bypass {
		return AccessResult{OK: true}, nil
	}
	op := strings.TrimSpace(in.Operation)
	pts, _ := operationPoints(op)
	if pts <= 0 {
		return AccessResult{OK: true}, nil
	}
	if len(in.RoleNames) == 0 && in.UserID != uuid.Nil {
		names, _ := s.userRoleNames(ctx, in.UserID)
		in.RoleNames = names
	}
	lookup := in
	lookup.SkipRisk = true
	lookup.IgnoreTicket = true
	lookup.Operation = ""
	ev, err := s.Evaluate(ctx, lookup)
	if err != nil {
		return AccessResult{OK: true}, nil
	}
	if !ev.OK {
		ev = AccessResult{OK: true}
	}
	in.Operation = op
	if ev.MaxRisk > 0 {
		s.applyOpRisk(ctx, in, &ev)
	}
	if ev.OK {
		tags, _ := s.UserTags(ctx, in.UserID)
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
	if score > res.MaxRisk {
		res.OK = false
		res.DeniedByRisk = true
		if res.RiskAction == "" {
			res.RiskAction = "deny"
		}
	}
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
	if res.BindingID != nil {
		payload["binding_id"] = res.BindingID.String()
	}
	_ = s.aud.Record(ctx, &in.UserID, "access.risk.evaluated", "asset", in.AssetID.String(), in.ClientIP, "", payload)
}
