package policy

import (
	"fmt"
	"strings"

	"github.com/keeppam/auth/internal/tagpath"
)

func normalizeMatchMode(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "all":
		return "all", nil
	case "any":
		return "any", nil
	default:
		return "", fmt.Errorf("asset_match_mode must be all or any")
	}
}

// tagACLSQL is a WHERE fragment: inherited tag binding matches the asset's tags.
// assetTagsParam is a query placeholder such as "$2" (text[] of the asset's tags).
func tagACLSQL(assetTagsParam string) string {
	return `(b.asset_id IS NULL AND cardinality(b.asset_match_tags)>0 AND (
		(COALESCE(b.asset_match_mode,'all') <> 'any' AND ` + assetTagsParam + `::text[] @> b.asset_match_tags)
		OR
		(COALESCE(b.asset_match_mode,'all') = 'any' AND b.asset_match_tags && ` + assetTagsParam + `::text[])
	))`
}

func tagsMatch(mode string, assetTags, selector []string) bool {
	selector = normalizeTags(selector)
	if len(selector) == 0 {
		return false
	}
	have := toSet(expandTagAncestors(assetTags))
	if mode == "any" {
		for _, t := range selector {
			if _, ok := have[t]; ok {
				return true
			}
		}
		return false
	}
	return hasAll(have, selector)
}

func expandTagAncestors(tags []string) []string {
	return tagpath.ExpandAncestors(tags)
}
