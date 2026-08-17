package sshcmd

import (
	"context"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/opapprove"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/sshproxy"
)

type Deps struct {
	Policy   *policy.Service
	Ops      *opapprove.Service
	Sessions *sessionsvc.Service
	Audit    *audit.Service
}

type Meta struct {
	UserID     uuid.UUID
	AssetID    uuid.UUID
	SessionID  uuid.UUID
	Username   string
	AssetName  string
	IP         string
	Roles      []string
	Bypass     bool
	BreakGlass bool
	TicketID   string
	Snap       *policy.Snapshot
	Inject     func([]byte)
}

func (d Deps) BuildOpts(ctx context.Context, m Meta) sshproxy.SessionOpts {
	opts := sshproxy.SessionOpts{LocalInject: m.Inject}
	if d.Policy == nil {
		return opts
	}
	var pack policy.CommandPack
	hasPack := false
	check := policy.AccessCheck{
		UserID: m.UserID, AssetID: m.AssetID, RoleNames: m.Roles, Bypass: m.Bypass, TicketID: m.TicketID, Snapshot: m.Snap,
	}
	if m.Snap != nil {
		if m.Snap.CommandPolicyPackID != nil {
			if p, perr := d.Policy.GetCommandPack(ctx, *m.Snap.CommandPolicyPackID); perr == nil {
				pack, hasPack = p, true
			}
		}
	} else {
		ev, err := d.Policy.Evaluate(ctx, policy.AccessCheck{
			UserID: m.UserID, AssetID: m.AssetID, RoleNames: m.Roles, Bypass: m.Bypass, TicketID: m.TicketID, SkipRisk: true,
		})
		if err == nil && ev.OK {
			if ev.CommandPolicyPackID != nil {
				if p, perr := d.Policy.GetCommandPack(ctx, *ev.CommandPolicyPackID); perr == nil {
					pack, hasPack = p, true
				}
			}
		}
	}
	opts.QuietEcho = true
	held := false
	guard := sshproxy.NewCommandGuard(func(line string) bool {
		held = false
		v := d.Policy.EvaluateSSHLine(ctx, check, pack, hasPack, line)
		if v.Allow {
			d.logPTY(ctx, m.SessionID, line, v)
			return true
		}
		if v.Kind != policy.SSHKindApproval || d.Ops == nil {
			return false
		}
		held = true
		if !opapprove.SkipWait(m.BreakGlass, m.Snap) && m.Inject != nil {
			m.Inject([]byte("\x1b[33m[KeepPAM] waiting for approval (60s)\x1b[0m\r\n"))
		}
		hr := d.Ops.Hold(ctx, opapprove.HoldInput{
			SessionID:  m.SessionID,
			UserID:     m.UserID,
			AssetID:    m.AssetID,
			Username:   m.Username,
			AssetName:  m.AssetName,
			Method:     "SSH",
			Path:       line,
			Object:     v.Operation,
			PackName:   pack.Name,
			Channel:    "ssh",
			IP:         m.IP,
			BreakGlass: m.BreakGlass,
			Snapshot:   m.Snap,
		})
		payload := v.Payload(line)
		if hr.Rec.ID != uuid.Nil {
			payload["approval_id"] = hr.Rec.ID.String()
		}
		if hr.Allow {
			if m.Inject != nil {
				m.Inject([]byte("\x1b[32m[KeepPAM] approved\x1b[0m\r\n"))
			}
			payload["code"] = "approved"
			payload["reason"] = "command approved: " + line
			if d.Sessions != nil {
				_ = d.Sessions.AddEvent(ctx, m.SessionID, "command_approved", payload)
			}
			d.logPTY(ctx, m.SessionID, line, v)
			return true
		}
		if hr.Code != "" {
			payload["code"] = hr.Code
		}
		if hr.Reason != "" {
			payload["reason"] = hr.Reason
		}
		evt := "command_denied"
		if hr.Code == "approval_timeout" || hr.Code == "approval_required" {
			evt = "command_approval"
		}
		if d.Sessions != nil {
			_ = d.Sessions.AddEvent(ctx, m.SessionID, evt, payload)
		}
		return false
	})
	opts.Guard = guard
	opts.OnDenied = func(line string) {
		if held {
			return
		}
		bg := context.Background()
		v := d.Policy.EvaluateSSHLine(bg, check, pack, hasPack, line)
		if d.Audit != nil {
			_ = d.Audit.Record(bg, &m.UserID, v.AuditAction(), "session", m.SessionID.String(), m.IP, "ssh", v.Payload(line))
		}
		if d.Sessions != nil {
			_ = d.Sessions.AddEvent(bg, m.SessionID, v.EventType(), v.Payload(line))
		}
	}
	return opts
}

func (d Deps) logPTY(ctx context.Context, sessionID uuid.UUID, line string, v policy.SSHLineVerdict) {
	if d.Sessions == nil {
		return
	}
	p := v.Payload(line)
	p["source"] = "pty"
	_ = d.Sessions.AddEvent(ctx, sessionID, "command", p)
}
