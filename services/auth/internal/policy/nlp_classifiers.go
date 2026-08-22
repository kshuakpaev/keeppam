package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	maxNlpClassifiers   = 16
	maxNlpKeywordsLen   = 4096
	maxNlpKeywordTokens = 64
)

type NlpClassifier struct {
	Name     string `json:"name"`
	Keywords string `json:"keywords"`
	MinHits  int    `json:"min_hits"`
}

type CompiledNlpClassifier struct {
	Name     string
	Keywords []string
	MinHits  int
}

func parseNlpKeywords(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("keywords required")
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '|' || r == ','
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("keywords required")
	}
	if len(parts) > maxNlpKeywordTokens {
		return nil, fmt.Errorf("at most %d keywords", maxNlpKeywordTokens)
	}
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("keywords required")
	}
	return out, nil
}

func NormalizeNlpClassifiers(raw []NlpClassifier) ([]NlpClassifier, error) {
	if len(raw) > maxNlpClassifiers {
		return nil, fmt.Errorf("dlp_classifiers: at most %d classifiers", maxNlpClassifiers)
	}
	seen := map[string]struct{}{}
	out := make([]NlpClassifier, 0, len(raw))
	for i, c := range raw {
		name := strings.TrimSpace(c.Name)
		keywords := strings.TrimSpace(c.Keywords)
		if name == "" && keywords == "" {
			continue
		}
		if name == "" || keywords == "" {
			return nil, fmt.Errorf("dlp_classifiers[%d]: name and keywords required", i)
		}
		if !reDlpPatternName.MatchString(name) {
			return nil, fmt.Errorf("dlp_classifiers[%d]: invalid name %q", i, name)
		}
		if strings.HasPrefix(name, "nlp_") {
			return nil, fmt.Errorf("dlp_classifiers[%d]: name %q reserved", i, name)
		}
		if len(keywords) > maxNlpKeywordsLen {
			return nil, fmt.Errorf("dlp_classifiers[%d]: keywords too long", i)
		}
		if _, err := parseNlpKeywords(keywords); err != nil {
			return nil, fmt.Errorf("dlp_classifiers[%d]: %w", i, err)
		}
		minHits := c.MinHits
		if minHits <= 0 {
			minHits = 1
		}
		if minHits > 8 {
			return nil, fmt.Errorf("dlp_classifiers[%d]: min_hits must be 1..8", i)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("dlp_classifiers: duplicate name %q", name)
		}
		if _, ok := builtinNlpCategories[name]; ok {
			return nil, fmt.Errorf("dlp_classifiers[%d]: name %q reserved", i, name)
		}
		seen[name] = struct{}{}
		out = append(out, NlpClassifier{Name: name, Keywords: keywords, MinHits: minHits})
	}
	return out, nil
}

func CompileNlpClassifiers(raw []NlpClassifier) ([]CompiledNlpClassifier, error) {
	norm, err := NormalizeNlpClassifiers(raw)
	if err != nil {
		return nil, err
	}
	out := make([]CompiledNlpClassifier, 0, len(norm))
	for _, c := range norm {
		kws, err := parseNlpKeywords(c.Keywords)
		if err != nil {
			return nil, err
		}
		minHits := c.MinHits
		if minHits <= 0 {
			minHits = 1
		}
		out = append(out, CompiledNlpClassifier{Name: c.Name, Keywords: kws, MinHits: minHits})
	}
	return out, nil
}

func (s *Service) ListNlpClassifiers(ctx context.Context, policyID uuid.UUID) ([]NlpClassifier, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT name, keywords, min_hits FROM dlp_classifiers
		WHERE access_policy_id=$1 ORDER BY sort_order, name`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NlpClassifier
	for rows.Next() {
		var c NlpClassifier
		if err := rows.Scan(&c.Name, &c.Keywords, &c.MinHits); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if out == nil {
		out = []NlpClassifier{}
	}
	return out, rows.Err()
}

func (s *Service) ReplaceNlpClassifiers(ctx context.Context, policyID uuid.UUID, raw []NlpClassifier) error {
	if s == nil || s.db == nil {
		return nil
	}
	norm, err := NormalizeNlpClassifiers(raw)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM dlp_classifiers WHERE access_policy_id=$1`, policyID); err != nil {
		return err
	}
	for i, c := range norm {
		if _, err := tx.Exec(ctx, `
			INSERT INTO dlp_classifiers (id, access_policy_id, name, keywords, min_hits, sort_order)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			uuid.New(), policyID, c.Name, c.Keywords, c.MinHits, i); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) attachNlpClassifiers(ctx context.Context, p *AccessPolicy) error {
	if p == nil {
		return nil
	}
	pats, err := s.ListNlpClassifiers(ctx, p.ID)
	if err != nil {
		return err
	}
	p.NlpClassifiers = pats
	return nil
}

func compileSnapshotClassifiers(raw []NlpClassifier) []CompiledNlpClassifier {
	if len(raw) == 0 {
		return nil
	}
	out, err := CompileNlpClassifiers(raw)
	if err != nil {
		return nil
	}
	return out
}

func (s *Service) loadNlpClassifiersForSnapshot(ctx context.Context, sn *Snapshot) {
	if s == nil || sn == nil || sn.AccessPolicyID == nil || len(sn.NlpClassifiers) > 0 {
		return
	}
	pats, err := s.ListNlpClassifiers(ctx, *sn.AccessPolicyID)
	if err != nil {
		return
	}
	sn.NlpClassifiers = pats
}
