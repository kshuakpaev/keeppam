package geo

import (
	"fmt"
	"strings"
	"time"
)

type PromoteStep struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"` // ok | warn | block | manual
	Detail  string `json:"detail,omitempty"`
	Command string `json:"command,omitempty"`
}

type PromotePlan struct {
	SiteID      string        `json:"site_id"`
	Role        string        `json:"role"`
	Ready       bool          `json:"ready"`
	Steps       []PromoteStep `json:"steps"`
	GeneratedAt time.Time     `json:"generated_at"`
	Hint        string        `json:"hint"`
}

// BuildPromotePlan assembles a cutover checklist (does not execute promote).
func BuildPromotePlan(cfg Config, rec RecordingsStatus, st Status) PromotePlan {
	cfg.Role = NormalizeRole(cfg.Role)
	plan := PromotePlan{
		SiteID:      cfg.SiteID,
		Role:        cfg.Role,
		GeneratedAt: time.Now().UTC(),
		Hint:        "docs/geo-ha.txt; execute via scripts/geo-promote.sh after review",
	}
	if cfg.Role == RolePrimary {
		plan.Steps = []PromoteStep{{
			ID: "already_primary", Title: "Site already primary", Status: "ok",
			Detail: "no promote needed",
		}}
		plan.Ready = true
		return plan
	}
	if cfg.Role != RoleStandby {
		plan.Steps = append(plan.Steps, PromoteStep{
			ID: "role", Title: "Site role", Status: "block",
			Detail: fmt.Sprintf("expected standby, got %q", cfg.Role),
		})
		return plan
	}

	// PG lag / recovery
	pgStatus := "manual"
	pgDetail := "confirm site A is down or in planned maintenance"
	if st.ReplicaProbe == "ok" && st.InRecovery != nil && *st.InRecovery {
		pgStatus = "ok"
		if st.LagSeconds != nil {
			pgDetail = fmt.Sprintf("standby PG in recovery, lag %.1fs", *st.LagSeconds)
		}
		if st.LagOK != nil && !*st.LagOK {
			pgStatus = "warn"
			pgDetail += " — lag exceeds max; consider waiting"
		}
	} else if st.ReplicaProbe == "error" {
		pgStatus = "block"
		pgDetail = st.ReplicaError
	}
	plan.Steps = append(plan.Steps, PromoteStep{
		ID: "pg_replica", Title: "PostgreSQL standby healthy", Status: pgStatus, Detail: pgDetail,
		Command: "docker compose exec postgres pg_ctl promote -D /var/lib/postgresql/data",
	})

	// Recordings
	recStatus := "manual"
	recDetail := rec.Hint
	switch rec.Mode {
	case "s3":
		if rec.S3Bucket != "" {
			recStatus = "ok"
			recDetail = fmt.Sprintf("S3 bucket %s — verify replication caught up", rec.S3Bucket)
		}
	case "rsync":
		if rec.RsyncTarget != "" {
			recStatus = "warn"
			if rec.LastSync != nil && rec.LastSync.Error == "" {
				recStatus = "ok"
				recDetail = fmt.Sprintf("last rsync %s (%d files)", rec.LastSync.At.Format(time.RFC3339), rec.LastSync.Files)
			} else {
				recDetail = "run recordings sync before cutover"
			}
		}
	default:
		recStatus = "warn"
		recDetail = "no geo recordings sync — sessions on B may lack replay until restore"
	}
	plan.Steps = append(plan.Steps, PromoteStep{
		ID: "recordings", Title: "Recordings replicated", Status: recStatus, Detail: recDetail,
		Command: "./scripts/geo-recordings-sync.sh",
	})

	plan.Steps = append(plan.Steps,
		PromoteStep{
			ID: "promote_pg", Title: "Promote PostgreSQL", Status: "manual",
			Command: "./scripts/geo-promote.sh --pg-only",
		},
		PromoteStep{
			ID: "flip_role", Title: "Set KEEPPAM_SITE_ROLE=primary and restart", Status: "manual",
			Command: "./scripts/geo-promote.sh --role-only",
		},
		PromoteStep{
			ID: "dns", Title: "Switch DNS/VIP to this site edge", Status: "manual",
			Detail: "operator action",
		},
		PromoteStep{
			ID: "smoke", Title: "Smoke: login, JIT, SSH session", Status: "manual",
			Detail: "make acceptance-smoke or docs/kp-acceptance.txt",
		},
	)

	plan.Ready = true
	for _, step := range plan.Steps {
		if step.Status == "block" {
			plan.Ready = false
			break
		}
	}
	if cfg.SiteID == "" {
		plan.Ready = false
		plan.Steps = append([]PromoteStep{{
			ID: "site_id", Title: "KEEPPAM_SITE_ID set", Status: "block",
		}}, plan.Steps...)
	}
	_ = strings.TrimSpace
	return plan
}
