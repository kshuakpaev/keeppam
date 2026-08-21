package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/adjit"
	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/store"
)

func (s *Service) createADAccountsJob(ctx context.Context, actorID uuid.UUID, in CreateJobInput, ip, ua string) (Job, error) {
	if s.resolve == nil {
		return Job{}, fmt.Errorf("AD/LDAP directory not configured")
	}
	dir, err := s.resolve(ctx)
	if err != nil {
		return Job{}, err
	}
	if strings.TrimSpace(dir.URL) == "" || strings.TrimSpace(dir.UserBaseDN) == "" {
		return Job{}, fmt.Errorf("configure LDAP URL and user base DN (Config → Auth)")
	}
	scope := "ldap"
	if tid := strings.TrimSpace(in.TargetAssetID); tid != "" {
		aid, err := uuid.Parse(tid)
		if err != nil {
			return Job{}, fmt.Errorf("invalid target_asset_id")
		}
		if _, err := s.assets.Get(ctx, aid); err != nil {
			return Job{}, fmt.Errorf("target asset: %w", err)
		}
		scope = aid.String()
	}
	groups := strings.Join(in.GroupDNs, ",")
	if len(groups) > 2000 {
		groups = groups[:2000]
	}
	id := store.NewID()
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO discovery_jobs (id, kind, cidr, ports, status, total_hosts, created_at, created_by)
		VALUES ($1,'ad_accounts',$2,$3,'pending',1,NOW(),$4)`,
		id, scope, groups, actorID)
	if err != nil {
		return Job{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "discovery.job.created", "discovery_job", id.String(), ip, ua, map[string]any{
		"kind": "ad_accounts", "scope": scope, "groups": in.GroupDNs,
	})
	return s.GetJob(ctx, id)
}

func (s *Service) runADAccountsJob(ctx context.Context, job Job) error {
	if s.resolve == nil {
		return fmt.Errorf("AD/LDAP directory not configured")
	}
	dir, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	var extra []string
	if strings.TrimSpace(job.Ports) != "" {
		for _, g := range strings.Split(job.Ports, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				extra = append(extra, g)
			}
		}
	}
	users, err := adjit.SearchPrivileged(dir, extra)
	if err != nil {
		return err
	}
	host, port := ldapHostPort(dir.URL)
	found := 0
	for _, u := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		details, _ := json.Marshal(map[string]any{
			"dn": u.DN, "display_name": u.DisplayName, "admin_count": u.AdminCount,
			"member_of": u.MemberOf, "reasons": u.Reasons,
		})
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO discovery_candidates
				(id, job_id, address, port, protocol, username, source_asset_id, details, privileged, created_at)
			VALUES ($1,$2,$3,$4,'ldap',$5,NULL,$6,TRUE,NOW())
			ON CONFLICT (job_id, address, port, username) DO UPDATE
			SET details=EXCLUDED.details, privileged=TRUE`,
			store.NewID(), job.ID, host, port, u.Username, details)
		if err != nil {
			continue
		}
		found++
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE discovery_jobs SET status='done', scanned_hosts=1, open_ports=$2, finished_at=NOW(), error='' WHERE id=$1`,
		job.ID, found)
	return err
}

func ldapHostPort(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, 389
	}
	host := u.Hostname()
	port := 389
	if u.Scheme == "ldaps" {
		port = 636
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			port = n
		}
	}
	if host == "" {
		host = u.Host
	}
	return host, port
}

func (s *Service) importADAccountCandidate(ctx context.Context, actorID uuid.UUID, c Candidate, ip, ua string) (ImportResult, error) {
	if c.ImportedAccountID != nil {
		acc, err := s.assets.GetAccount(ctx, *c.ImportedAccountID)
		if err != nil {
			return ImportResult{}, err
		}
		return ImportResult{Kind: "account", Account: &acc}, nil
	}
	targetID, err := s.resolveADImportTarget(ctx, c)
	if err != nil {
		return ImportResult{}, err
	}
	dn := detailString(c.Details, "dn")
	if acc, err := s.assets.FindAccountByIdentity(ctx, targetID, c.Username, dn); err == nil {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE discovery_candidates SET imported_account_id=$2, imported_asset_id=$3 WHERE id=$1`,
			c.ID, acc.ID, targetID)
		return ImportResult{Kind: "account", Account: &acc}, nil
	}
	desc := "Discovered AD privileged account (no secret — set via rotate)"
	acc, err := s.assets.CreateAccount(ctx, actorID, targetID, assets.CreateAccountInput{
		Username:    c.Username,
		AuthMethod:  "password",
		Description: desc,
		ADUserDN:    dn,
	}, ip, ua)
	if err != nil {
		return ImportResult{}, err
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE discovery_candidates SET imported_account_id=$2, imported_asset_id=$3 WHERE id=$1`,
		c.ID, acc.ID, targetID)
	_ = s.aud.Record(ctx, &actorID, "discovery.account.imported", "asset_account", acc.ID.String(), ip, ua, map[string]any{
		"candidate_id": c.ID.String(), "asset_id": targetID.String(), "username": c.Username,
		"ad_user_dn": dn, "privileged": true, "source": "ad_accounts",
	})
	return ImportResult{Kind: "account", Account: &acc}, nil
}

func (s *Service) resolveADImportTarget(ctx context.Context, c Candidate) (uuid.UUID, error) {
	if c.SourceAssetID != nil {
		return *c.SourceAssetID, nil
	}
	job, err := s.GetJob(ctx, c.JobID)
	if err != nil {
		return uuid.Nil, err
	}
	if id, err := uuid.Parse(strings.TrimSpace(job.CIDR)); err == nil {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("set target_asset_id when starting AD discovery (asset to attach vault accounts)")
}

func detailString(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}
