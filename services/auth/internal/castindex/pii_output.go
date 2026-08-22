package castindex

import (
	"sort"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
)

type outputPIIStats struct {
	denied    int
	masked    int
	auditOnly int
	kinds     map[string]struct{}
}

func applyContentDLP(c policy.ContentDLP, text string) (line string, skip bool, st *outputPIIStats) {
	out, deny, kinds := policy.ApplyContentDLP(c, text)
	if len(kinds) == 0 {
		return text, false, nil
	}
	s := &outputPIIStats{kinds: map[string]struct{}{}}
	for _, k := range kinds {
		s.kinds[k] = struct{}{}
	}
	if deny {
		s.denied = 1
		return "", true, s
	}
	if out != text {
		s.masked = 1
		return out, false, s
	}
	if c.NLP.Active() && c.NLP.Action == "audit" {
		s.auditOnly = 1
	}
	return text, false, s
}

func mergePIIStats(dst *outputPIIStats, src *outputPIIStats) {
	if src == nil {
		return
	}
	if dst.kinds == nil {
		dst.kinds = map[string]struct{}{}
	}
	dst.denied += src.denied
	dst.masked += src.masked
	dst.auditOnly += src.auditOnly
	for k := range src.kinds {
		dst.kinds[k] = struct{}{}
	}
}

func contentDLP(row sessionsvc.Session) policy.ContentDLP {
	if row.PolicySnapshot == nil {
		return policy.ContentDLP{}
	}
	return row.PolicySnapshot.ContentDLP()
}

func dlpPayload(total *outputPIIStats, via string) map[string]any {
	if total == nil || len(total.kinds) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(total.kinds))
	for k := range total.kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	ev := map[string]any{"via": via, "kinds": kinds}
	if total.denied > 0 {
		ev["denied_lines"] = total.denied
	}
	if total.masked > 0 {
		ev["action"] = "mask"
		ev["masked_lines"] = total.masked
	} else if total.auditOnly > 0 {
		ev["action"] = "audit"
		ev["audit_lines"] = total.auditOnly
	}
	return ev
}
