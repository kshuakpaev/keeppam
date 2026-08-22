package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/store"
	winrmpkg "github.com/keeppam/auth/internal/winrm"
)

func (s *Service) createWinRMAccountsJob(ctx context.Context, actorID uuid.UUID, in CreateJobInput, ip, ua string) (Job, error) {
	targets, err := s.resolveWinRMTargets(ctx, in.AssetIDs)
	if err != nil {
		return Job{}, err
	}
	if len(targets) == 0 {
		return Job{}, fmt.Errorf("no RDP assets with vault credentials to scan")
	}
	if len(targets) > 100 {
		return Job{}, fmt.Errorf("too many assets (%d, max 100)", len(targets))
	}
	scope := "rdp-assets"
	if len(in.AssetIDs) > 0 {
		scope = "assets:" + strings.Join(in.AssetIDs, ",")
		if len(scope) > 2000 {
			scope = scope[:2000] + "…"
		}
	}
	mode := strings.TrimSpace(in.Ports)
	if mode == "" {
		mode = "winrm,sam"
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO discovery_jobs (id, kind, cidr, ports, status, total_hosts, created_at, created_by)
		VALUES ($1,'winrm_accounts',$2,$3,'pending',$4,NOW(),$5)`,
		id, scope, mode, len(targets), actorID)
	if err != nil {
		return Job{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "discovery.job.created", "discovery_job", id.String(), ip, ua, map[string]any{
		"kind": "winrm_accounts", "scope": scope, "total_hosts": len(targets), "mode": mode,
	})
	return s.GetJob(ctx, id)
}

func (s *Service) resolveWinRMTargets(ctx context.Context, assetIDs []string) ([]scanTarget, error) {
	filter := []uuid.UUID{}
	for _, raw := range assetIDs {
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid asset_id %q", raw)
		}
		filter = append(filter, id)
	}
	q := `
		SELECT a.id, acc.id, a.name, a.address, a.port
		FROM assets a
		JOIN LATERAL (
			SELECT id FROM asset_accounts
			WHERE asset_id=a.id AND status='active' AND secret_enc IS NOT NULL AND length(secret_enc)>0
			ORDER BY username LIMIT 1
		) acc ON true
		WHERE a.status='active' AND a.protocol='rdp'`
	args := []any{}
	if len(filter) > 0 {
		q += ` AND a.id = ANY($1)`
		args = append(args, filter)
	}
	q += ` ORDER BY a.name`
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scanTarget
	for rows.Next() {
		var t scanTarget
		if err := rows.Scan(&t.AssetID, &t.AccountID, &t.Name, &t.Address, &t.Port); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) runWinRMAccountsJob(ctx context.Context, job Job) error {
	var assetIDs []string
	if strings.HasPrefix(job.CIDR, "assets:") {
		assetIDs = strings.Split(strings.TrimPrefix(job.CIDR, "assets:"), ",")
	}
	targets, err := s.resolveWinRMTargets(ctx, assetIDs)
	if err != nil {
		return err
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE discovery_jobs SET total_hosts=$2 WHERE id=$1`, job.ID, len(targets))
	tryWinRM := strings.Contains(strings.ToLower(job.Ports), "winrm")
	trySAM := strings.Contains(strings.ToLower(job.Ports), "sam")

	found := 0
	for i, t := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, scanErr := s.scanWinRMAssetAccounts(ctx, job.ID, t, tryWinRM, trySAM)
		found += n
		msg := ""
		if scanErr != nil {
			msg = truncateErr(fmt.Sprintf("%s: %v", t.Name, scanErr))
		}
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE discovery_jobs SET scanned_hosts=$2, open_ports=$3, error=$4 WHERE id=$1`,
			job.ID, i+1, found, msg)
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE discovery_jobs SET status='done', scanned_hosts=$2, open_ports=$3, finished_at=NOW(), error='' WHERE id=$1`,
		job.ID, len(targets), found)
	return err
}

func (s *Service) scanWinRMAssetAccounts(ctx context.Context, jobID uuid.UUID, t scanTarget, tryWinRM, trySAM bool) (int, error) {
	creds, err := s.assets.GetTargetCreds(ctx, t.AssetID, t.AccountID)
	if err != nil {
		return 0, err
	}
	host := winrmpkg.NormalizeHost(t.Address)
	user := creds.Account.Username
	pass := creds.Secret

	var users []winrmpkg.LocalUser
	var sourceErr error
	if tryWinRM {
		if out, err := winrmpkg.RunPowerShell(host, winrmpkg.DefaultHTTPPort, false, false, user, pass, winrmpkg.DiscoverScript()); err == nil {
			if u, perr := winrmpkg.ParseDiscoverJSON(out); perr == nil {
				users = u
			} else {
				sourceErr = perr
			}
		} else {
			sourceErr = err
		}
		if len(users) == 0 {
			if out, err2 := winrmpkg.RunPowerShellTLS(host, winrmpkg.DefaultHTTPSPort, user, pass, winrmpkg.DiscoverScript()); err2 == nil {
				if u, perr := winrmpkg.ParseDiscoverJSON(out); perr == nil {
					users, sourceErr = u, nil
				}
			}
		}
	}
	if len(users) == 0 && trySAM {
		if u, err := s.discoverSAMViaSSH(ctx, creds); err == nil {
			users = u
			sourceErr = nil
		} else if sourceErr == nil {
			sourceErr = err
		}
	}
	if len(users) == 0 {
		if sourceErr != nil {
			return 0, sourceErr
		}
		return 0, fmt.Errorf("no local users discovered")
	}

	n := 0
	for _, u := range users {
		details, _ := json.Marshal(map[string]any{
			"sid": u.SID, "source": u.Source, "enabled": u.Enabled,
		})
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO discovery_candidates
				(id, job_id, address, port, protocol, username, source_asset_id, details, privileged, created_at)
			VALUES ($1,$2,$3,$4,'winrm',$5,$6,$7,$8,NOW())
			ON CONFLICT (job_id, address, port, username) DO UPDATE
			SET details=EXCLUDED.details, privileged=EXCLUDED.privileged, source_asset_id=EXCLUDED.source_asset_id`,
			store.NewID(), jobID, t.Address, t.Port, u.Name, t.AssetID, details, u.Privileged)
		if err != nil {
			continue
		}
		n++
	}
	return n, nil
}

func (s *Service) discoverSAMViaSSH(ctx context.Context, creds assets.TargetCreds) ([]winrmpkg.LocalUser, error) {
	client, err := s.assets.DialSSH(ctx, creds)
	if err != nil {
		mgmt := creds
		mgmt.Asset.Port = 22
		mgmt.Asset.Protocol = "ssh"
		client, err = s.assets.DialSSH(ctx, mgmt)
		if err != nil {
			return nil, fmt.Errorf("sam ssh: %w", err)
		}
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	netOut, err := sess.CombinedOutput("net user")
	if err != nil && len(netOut) == 0 {
		return nil, fmt.Errorf("net user: %w", err)
	}
	sess2, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess2.Close()
	admOut, _ := sess2.CombinedOutput("net localgroup administrators")
	return winrmpkg.ParseSAMNetUser(string(netOut), string(admOut))
}
