package geo

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type DrillCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | warn | skip
	Detail string `json:"detail,omitempty"`
}

type DrillReport struct {
	SiteID      string       `json:"site_id"`
	Role        string       `json:"role"`
	OK          bool         `json:"ok"`
	Checks      []DrillCheck `json:"checks"`
	GeneratedAt time.Time    `json:"generated_at"`
	Hint        string       `json:"hint"`
}

// RunDrill builds SOW-GEO-HA phase 3+ acceptance checks from local probe state.
func RunDrill(cfg Config, st Status, rec RecordingsStatus, ws WitnessStatus) DrillReport {
	cfg.Role = NormalizeRole(cfg.Role)
	rep := DrillReport{
		SiteID:      cfg.SiteID,
		Role:        cfg.Role,
		GeneratedAt: time.Now().UTC(),
		Hint:        "docs/geo-ha-cutover.txt; scripts/geo-drill.sh",
	}
	add := func(name, status, detail string) {
		rep.Checks = append(rep.Checks, DrillCheck{Name: name, Status: status, Detail: detail})
		if status == "fail" {
			rep.OK = false
		}
	}
	rep.OK = true

	if strings.TrimSpace(cfg.SiteID) == "" {
		add("site_id", "fail", "KEEPPAM_SITE_ID unset")
	} else {
		add("site_id", "pass", cfg.SiteID)
	}

	switch cfg.Role {
	case RolePrimary, RoleStandby, RoleStandalone:
		add("site_role", "pass", cfg.Role)
	default:
		add("site_role", "fail", "invalid role")
	}

	if cfg.IsStandby() {
		if st.AllowsWrites {
			add("standby_fence", "fail", "standby must not allow writes")
		} else {
			add("standby_fence", "pass", "session writes fenced")
		}
		if st.ReplicaProbe == "ok" && st.InRecovery != nil && *st.InRecovery {
			detail := "PG in recovery"
			if st.LagSeconds != nil {
				detail = fmt.Sprintf("lag %.1fs", *st.LagSeconds)
			}
			stt := "pass"
			if st.LagOK != nil && !*st.LagOK {
				stt = "warn"
			}
			add("pg_replica_lag", stt, detail)
		} else if st.ReplicaProbe == "error" {
			add("pg_replica_lag", "warn", st.ReplicaError)
		} else {
			add("pg_replica_lag", "skip", "no replica DSN")
		}
	} else if cfg.Role == RolePrimary {
		if !st.AllowsWrites {
			add("primary_writes", "fail", "primary must allow writes")
		} else {
			add("primary_writes", "pass", "writes enabled")
		}
	}

	switch rec.Mode {
	case "s3", "rsync":
		add("recordings_sync", "pass", rec.Mode)
	default:
		add("recordings_sync", "warn", rec.Hint)
	}

	if ws.Mode != "off" {
		stt := "pass"
		if ws.SplitBrain {
			stt = "fail"
		} else if !ws.OK {
			stt = "warn"
		}
		add("witness_split_brain", stt, ws.SplitBrainDetail)
		if ws.Mode != "" {
			add("witness_mode", "pass", ws.Mode)
		}
	}

	return rep
}

// ProbePeer GETs peer /geoz (or path suffix) for cutover verification.
func ProbePeer(ctx context.Context, peerURL string) (siteID, role string, err error) {
	pi, err := ProbePeerInfo(ctx, peerURL)
	return pi.SiteID, pi.Role, err
}

// CutoverCheck verifies public URL points at expected site after DNS/VIP flip.
func CutoverCheck(ctx context.Context, publicURL, expectSiteID, expectRole string) DrillCheck {
	publicURL = strings.TrimSpace(publicURL)
	expectSiteID = strings.TrimSpace(expectSiteID)
	expectRole = NormalizeRole(expectRole)
	if publicURL == "" {
		return DrillCheck{Name: "cutover_public", Status: "skip", Detail: "public URL not set"}
	}
	sid, role, err := ProbePeer(ctx, publicURL)
	if err != nil {
		return DrillCheck{Name: "cutover_public", Status: "fail", Detail: err.Error()}
	}
	role = NormalizeRole(role)
	if expectSiteID != "" && sid != expectSiteID {
		return DrillCheck{Name: "cutover_public", Status: "fail",
			Detail: fmt.Sprintf("geoz site_id=%q want %q", sid, expectSiteID)}
	}
	if expectRole != "" && role != expectRole {
		return DrillCheck{Name: "cutover_public", Status: "fail",
			Detail: fmt.Sprintf("geoz role=%q want %q", role, expectRole)}
	}
	return DrillCheck{Name: "cutover_public", Status: "pass",
		Detail: fmt.Sprintf("site_id=%s role=%s", sid, role)}
}
