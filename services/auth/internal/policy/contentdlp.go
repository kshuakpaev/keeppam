package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const maxPIIScan = 256 * 1024

// NormalizePIIAction accepts "", mask, deny (off/none → empty).
func NormalizePIIAction(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "", nil
	case "mask":
		return "mask", nil
	case "deny":
		return "deny", nil
	default:
		return "", fmt.Errorf("pii_action must be mask, deny, or empty")
	}
}

type piiMatch struct {
	start, end int
	kind       string
}

var (
	reEmail = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	rePAN   = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	rePhone = regexp.MustCompile(`(?:\+|8)(?:[\s\-()]?\d){10,14}`)
	reSNILS = regexp.MustCompile(`\b\d{3}-\d{3}-\d{3} \d{2}\b`)
)

// ScanPII finds built-in PII kinds in s (email, pan, phone, snils). Does not log the values.
func ScanPII(s string) (kinds []string, masked string) {
	kinds, masked, _ = scanContent(s, nil)
	return kinds, masked
}

func scanCustomPatterns(s string, patterns []CompiledDlpPattern) (hits []piiMatch) {
	for _, p := range patterns {
		if p.Re == nil {
			continue
		}
		for _, loc := range p.Re.FindAllStringIndex(s, -1) {
			hits = append(hits, piiMatch{loc[0], loc[1], p.Name})
		}
	}
	return hits
}

func scanContent(s string, patterns []CompiledDlpPattern) (kinds []string, masked string, hits []piiMatch) {
	if s == "" {
		return nil, s, nil
	}
	if len(s) > maxPIIScan {
		s = s[:maxPIIScan]
	}
	hits = scanBuiltinPII(s)
	hits = append(hits, scanCustomPatterns(s, patterns)...)
	if len(hits) == 0 {
		return nil, s, nil
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start == hits[j].start {
			return hits[i].end > hits[j].end
		}
		return hits[i].start < hits[j].start
	})
	var kept []piiMatch
	end := -1
	seen := map[string]struct{}{}
	var order []string
	for _, h := range hits {
		if h.start < end {
			continue
		}
		kept = append(kept, h)
		end = h.end
		if _, ok := seen[h.kind]; !ok {
			seen[h.kind] = struct{}{}
			order = append(order, h.kind)
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for _, h := range kept {
		b.WriteString(s[pos:h.start])
		b.WriteString(maskMatch(s[h.start:h.end], h.kind))
		pos = h.end
	}
	b.WriteString(s[pos:])
	return order, b.String(), kept
}

func scanBuiltinPII(s string) []piiMatch {
	var hits []piiMatch
	for _, loc := range reEmail.FindAllStringIndex(s, -1) {
		hits = append(hits, piiMatch{loc[0], loc[1], "email"})
	}
	for _, loc := range rePAN.FindAllStringIndex(s, -1) {
		raw := s[loc[0]:loc[1]]
		digits := digitsOnly(raw)
		if looksLikePAN(digits) {
			hits = append(hits, piiMatch{loc[0], loc[1], "pan"})
		}
	}
	for _, loc := range rePhone.FindAllStringIndex(s, -1) {
		d := digitsOnly(s[loc[0]:loc[1]])
		if len(d) >= 11 && len(d) <= 15 && !looksLikePAN(d) {
			hits = append(hits, piiMatch{loc[0], loc[1], "phone"})
		}
	}
	for _, loc := range reSNILS.FindAllStringIndex(s, -1) {
		hits = append(hits, piiMatch{loc[0], loc[1], "snils"})
	}
	return hits
}

func maskMatch(val, kind string) string {
	switch kind {
	case "email", "pan", "phone", "snils":
		return maskPII(val, kind)
	default:
		return "***"
	}
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func looksLikePAN(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	switch digits[0] {
	case '2', '3', '4', '5', '6':
	default:
		return false
	}
	allSame := true
	for i := 1; i < n; i++ {
		if digits[i] != digits[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	return luhnOK(digits)
}

func luhnOK(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func maskPII(val, kind string) string {
	switch kind {
	case "pan":
		d := digitsOnly(val)
		if len(d) >= 4 {
			return strings.Repeat("*", 12) + d[len(d)-4:]
		}
	case "email":
		if i := strings.IndexByte(val, '@'); i > 0 {
			return string(val[0]) + "***@***"
		}
	case "phone":
		d := digitsOnly(val)
		if len(d) >= 2 {
			return "***" + d[len(d)-2:]
		}
	}
	return "***"
}

// ApplyPIIAction masks or denies built-in PII only. Empty action is a no-op.
func ApplyPIIAction(action, s string) (out string, deny bool, kinds []string) {
	return ApplyContentDLP(ContentDLP{Action: action}, s)
}

// ApplyContentDLP masks or denies built-in PII and custom regex patterns.
func ApplyContentDLP(c ContentDLP, s string) (out string, deny bool, kinds []string) {
	if !c.active() {
		return s, false, nil
	}
	kinds, masked, _ := scanContent(s, c.Patterns)
	if len(kinds) == 0 {
		return s, false, nil
	}
	if c.Action == "deny" {
		return s, true, kinds
	}
	return masked, false, kinds
}

// ApplyPIIRows scans SQL cells. On deny, rows are emptied.
func ApplyPIIRows(action string, rows [][]string) (out [][]string, deny bool, kinds []string) {
	return ApplyContentDLPRows(ContentDLP{Action: action}, rows)
}

// ApplyContentDLPRows scans SQL cells with custom patterns.
func ApplyContentDLPRows(c ContentDLP, rows [][]string) (out [][]string, deny bool, kinds []string) {
	if !c.active() {
		return rows, false, nil
	}
	seen := map[string]struct{}{}
	var order []string
	add := func(ks []string) {
		for _, k := range ks {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			order = append(order, k)
		}
	}
	if c.Action == "deny" {
		for _, row := range rows {
			for _, cell := range row {
				ks, _, _ := scanContent(cell, c.Patterns)
				if len(ks) > 0 {
					add(ks)
					return rows, true, order
				}
			}
		}
		return rows, false, nil
	}
	out = make([][]string, len(rows))
	for i, row := range rows {
		cp := append([]string(nil), row...)
		for j, cell := range cp {
			ks, masked, _ := scanContent(cell, c.Patterns)
			if len(ks) == 0 {
				continue
			}
			add(ks)
			cp[j] = masked
		}
		out[i] = cp
	}
	return out, false, order
}

func textualContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/javascript", "application/xml",
		"application/x-www-form-urlencoded", "application/graphql-response+json":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

// FilterHTTPBody applies PII action to a textual HTTP body.
func FilterHTTPBody(action, contentType string, body []byte) (out []byte, deny bool, kinds []string) {
	return FilterHTTPBodyDLP(ContentDLP{Action: action}, contentType, body)
}

// FilterHTTPBodyDLP applies content DLP to a textual HTTP body.
func FilterHTTPBodyDLP(c ContentDLP, contentType string, body []byte) (out []byte, deny bool, kinds []string) {
	if !c.active() {
		return body, false, nil
	}
	if !textualContentType(contentType) {
		return body, false, nil
	}
	s := string(body)
	ns, deny, kinds := ApplyContentDLP(c, s)
	if deny || len(kinds) == 0 {
		return body, deny, kinds
	}
	return []byte(ns), false, kinds
}
