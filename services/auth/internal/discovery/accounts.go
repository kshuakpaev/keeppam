package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/store"
)

type scanTarget struct {
	AssetID   uuid.UUID
	AccountID uuid.UUID
	Name      string
	Address   string
	Port      int
}

func (s *Service) createAccountsJob(ctx context.Context, actorID uuid.UUID, in CreateJobInput, ip, ua string) (Job, error) {
	targets, err := s.resolveAccountTargets(ctx, in.AssetIDs)
	if err != nil {
		return Job{}, err
	}
	if len(targets) == 0 {
		return Job{}, fmt.Errorf("no SSH assets with vault credentials to scan")
	}
	if len(targets) > 200 {
		return Job{}, fmt.Errorf("too many assets (%d, max 200)", len(targets))
	}
	scope := "ssh-assets"
	if len(in.AssetIDs) > 0 {
		scope = "assets:" + strings.Join(in.AssetIDs, ",")
		if len(scope) > 2000 {
			scope = scope[:2000] + "…"
		}
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO discovery_jobs (id, kind, cidr, ports, status, total_hosts, created_at, created_by)
		VALUES ($1,'accounts',$2,'22','pending',$3,NOW(),$4)`,
		id, scope, len(targets), actorID)
	if err != nil {
		return Job{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "discovery.job.created", "discovery_job", id.String(), ip, ua, map[string]any{
		"kind": "accounts", "scope": scope, "total_hosts": len(targets),
	})
	return s.GetJob(ctx, id)
}

func (s *Service) resolveAccountTargets(ctx context.Context, assetIDs []string) ([]scanTarget, error) {
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
		WHERE a.status='active' AND a.protocol='ssh'`
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

func (s *Service) runAccountsJob(ctx context.Context, job Job) error {
	var assetIDs []string
	if strings.HasPrefix(job.CIDR, "assets:") {
		assetIDs = strings.Split(strings.TrimPrefix(job.CIDR, "assets:"), ",")
	}
	targets, err := s.resolveAccountTargets(ctx, assetIDs)
	if err != nil {
		return err
	}
	_, _ = s.db.Pool.Exec(ctx, `UPDATE discovery_jobs SET total_hosts=$2 WHERE id=$1`, job.ID, len(targets))

	found := 0
	for i, t := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, scanErr := s.scanAssetAccounts(ctx, job.ID, t)
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

func (s *Service) scanAssetAccounts(ctx context.Context, jobID uuid.UUID, t scanTarget) (int, error) {
	creds, err := s.assets.GetTargetCreds(ctx, t.AssetID, t.AccountID)
	if err != nil {
		return 0, err
	}
	client, err := s.assets.DialSSH(ctx, creds)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	_ = sess.Setenv("LANG", "C")
	out, err := sess.CombinedOutput(`getent passwd 2>/dev/null || cat /etc/passwd`)
	if err != nil && len(out) == 0 {
		return 0, fmt.Errorf("passwd read: %w", err)
	}

	users := parsePasswd(out)
	n := 0
	for _, u := range users {
		details, _ := json.Marshal(map[string]any{
			"uid": u.UID, "gid": u.GID, "shell": u.Shell, "gecos": u.GECOS, "home": u.Home,
		})
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO discovery_candidates
				(id, job_id, address, port, protocol, username, source_asset_id, details, privileged, created_at)
			VALUES ($1,$2,$3,$4,'ssh',$5,$6,$7,$8,NOW())
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

type passwdUser struct {
	Name       string
	UID        int
	GID        int
	GECOS      string
	Home       string
	Shell      string
	Privileged bool
}

func parsePasswd(raw []byte) []passwdUser {
	lines := bytes.Split(raw, []byte("\n"))
	seen := map[string]struct{}{}
	var out []passwdUser
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		parts := strings.Split(string(line), ":")
		if len(parts) < 7 {
			continue
		}
		name := parts[0]
		if name == "" || name == "nobody" || name == "nfsnobody" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		shell := parts[6]
		if !includePasswdUser(name, uid, shell) {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, passwdUser{
			Name: name, UID: uid, GID: gid, GECOS: parts[4], Home: parts[5], Shell: shell,
			Privileged: isPrivilegedUser(name, uid),
		})
	}
	return out
}

func includePasswdUser(name string, uid int, shell string) bool {
	if name == "root" || uid == 0 {
		return true
	}
	if uid >= 1000 {
		return true
	}
	// low-UID service accounts with a real shell are interesting for PAM
	sh := strings.ToLower(shell)
	if strings.Contains(sh, "nologin") || strings.HasSuffix(sh, "/false") || sh == "" {
		return false
	}
	return uid > 0 && uid < 1000
}

func isPrivilegedUser(name string, uid int) bool {
	if uid == 0 {
		return true
	}
	switch strings.ToLower(name) {
	case "root", "admin", "administrator", "toor":
		return true
	default:
		return false
	}
}

func (s *Service) importAccountCandidate(ctx context.Context, actorID uuid.UUID, c Candidate, ip, ua string) (ImportResult, error) {
	if c.SourceAssetID == nil {
		return ImportResult{}, fmt.Errorf("candidate has no source asset")
	}
	if c.ImportedAccountID != nil {
		acc, err := s.assets.GetAccount(ctx, *c.ImportedAccountID)
		if err != nil {
			return ImportResult{}, err
		}
		return ImportResult{Kind: "account", Account: &acc}, nil
	}
	// already exists?
	if acc, err := s.assets.FindAccount(ctx, *c.SourceAssetID, c.Username); err == nil {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE discovery_candidates SET imported_account_id=$2 WHERE id=$1`, c.ID, acc.ID)
		return ImportResult{Kind: "account", Account: &acc}, nil
	}
	desc := "Discovered account (no secret — set via rotate/checkout)"
	if c.Privileged {
		desc = "Privileged · " + desc
	}
	acc, err := s.assets.CreateAccount(ctx, actorID, *c.SourceAssetID, assets.CreateAccountInput{
		Username:    c.Username,
		AuthMethod:  "password",
		Description: desc,
	}, ip, ua)
	if err != nil {
		return ImportResult{}, err
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE discovery_candidates SET imported_account_id=$2, imported_asset_id=$3 WHERE id=$1`,
		c.ID, acc.ID, *c.SourceAssetID)
	_ = s.aud.Record(ctx, &actorID, "discovery.account.imported", "asset_account", acc.ID.String(), ip, ua, map[string]any{
		"candidate_id": c.ID.String(), "asset_id": c.SourceAssetID.String(), "username": c.Username, "privileged": c.Privileged,
	})
	return ImportResult{Kind: "account", Account: &acc}, nil
}
