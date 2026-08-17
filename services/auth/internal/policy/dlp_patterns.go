package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	maxDlpPatterns   = 16
	maxDlpPatternLen = 512
)

var reDlpPatternName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type DlpPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

type CompiledDlpPattern struct {
	Name string
	Re   *regexp.Regexp
}

type ContentDLP struct {
	Action   string
	Patterns []CompiledDlpPattern
}

func NormalizeDlpPatterns(raw []DlpPattern) ([]DlpPattern, error) {
	if len(raw) > maxDlpPatterns {
		return nil, fmt.Errorf("dlp_patterns: at most %d patterns", maxDlpPatterns)
	}
	seen := map[string]struct{}{}
	out := make([]DlpPattern, 0, len(raw))
	for i, p := range raw {
		name := strings.TrimSpace(p.Name)
		pattern := strings.TrimSpace(p.Pattern)
		if name == "" && pattern == "" {
			continue
		}
		if name == "" || pattern == "" {
			return nil, fmt.Errorf("dlp_patterns[%d]: name and pattern required", i)
		}
		if !reDlpPatternName.MatchString(name) {
			return nil, fmt.Errorf("dlp_patterns[%d]: invalid name %q", i, name)
		}
		if len(pattern) > maxDlpPatternLen {
			return nil, fmt.Errorf("dlp_patterns[%d]: pattern too long", i)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("dlp_patterns[%d]: invalid regex: %w", i, err)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("dlp_patterns: duplicate name %q", name)
		}
		seen[name] = struct{}{}
		out = append(out, DlpPattern{Name: name, Pattern: pattern})
	}
	return out, nil
}

func CompileDlpPatterns(raw []DlpPattern) ([]CompiledDlpPattern, error) {
	norm, err := NormalizeDlpPatterns(raw)
	if err != nil {
		return nil, err
	}
	out := make([]CompiledDlpPattern, 0, len(norm))
	for _, p := range norm {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, err
		}
		out = append(out, CompiledDlpPattern{Name: p.Name, Re: re})
	}
	return out, nil
}

func (s *Service) ListDlpPatterns(ctx context.Context, policyID uuid.UUID) ([]DlpPattern, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT name, pattern FROM dlp_patterns
		WHERE access_policy_id=$1 ORDER BY sort_order, name`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DlpPattern
	for rows.Next() {
		var p DlpPattern
		if err := rows.Scan(&p.Name, &p.Pattern); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []DlpPattern{}
	}
	return out, rows.Err()
}

func (s *Service) ReplaceDlpPatterns(ctx context.Context, policyID uuid.UUID, raw []DlpPattern) error {
	if s == nil || s.db == nil {
		return nil
	}
	norm, err := NormalizeDlpPatterns(raw)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM dlp_patterns WHERE access_policy_id=$1`, policyID); err != nil {
		return err
	}
	for i, p := range norm {
		if _, err := tx.Exec(ctx, `
			INSERT INTO dlp_patterns (id, access_policy_id, name, pattern, sort_order)
			VALUES ($1,$2,$3,$4,$5)`,
			uuid.New(), policyID, p.Name, p.Pattern, i); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) attachDlpPatterns(ctx context.Context, p *AccessPolicy) error {
	if p == nil {
		return nil
	}
	pats, err := s.ListDlpPatterns(ctx, p.ID)
	if err != nil {
		return err
	}
	p.DlpPatterns = pats
	return nil
}

func compileSnapshotPatterns(raw []DlpPattern) []CompiledDlpPattern {
	if len(raw) == 0 {
		return nil
	}
	out, err := CompileDlpPatterns(raw)
	if err != nil {
		return nil
	}
	return out
}

func (sn *Snapshot) ContentDLP() ContentDLP {
	if sn == nil || sn.AdminBypass {
		return ContentDLP{}
	}
	return ContentDLP{
		Action:   sn.PIIAction,
		Patterns: compileSnapshotPatterns(sn.DlpPatterns),
	}
}

func (c ContentDLP) Active() bool {
	return c.Action == "mask" || c.Action == "deny"
}

func (c ContentDLP) active() bool {
	return c.Active()
}

func (s *Service) loadDlpPatternsForSnapshot(ctx context.Context, sn *Snapshot) {
	if s == nil || sn == nil || sn.AccessPolicyID == nil || len(sn.DlpPatterns) > 0 {
		return
	}
	pats, err := s.ListDlpPatterns(ctx, *sn.AccessPolicyID)
	if err != nil {
		return
	}
	sn.DlpPatterns = pats
}
