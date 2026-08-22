package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxNlpScan = 256 * 1024

var rePrivateKey = regexp.MustCompile(`(?i)-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----`)

var builtinNlpCategories = map[string][]string{
	"nlp_credentials": {
		"password", "passwd", "secret", "api key", "apikey", "access token", "bearer token",
		"client secret", "private key", "пароль", "секрет", "токен", "учётные данные",
	},
	"nlp_financial": {
		"bank account", "iban", "swift", "invoice", "payment", "wire transfer", "credit limit",
		"банковский сч", "реквизит", "оплата", "счёт на оплату", "перевод",
	},
	"nlp_personal_id": {
		"passport", "national id", "social security", "tax id", "ogrn", "ogrnip",
		"паспорт", "инн", "снils", "огрн", "удостоверение личности",
	},
	"nlp_health": {
		"diagnosis", "patient record", "medical history", "prescription", "hipaa",
		"диагноз", "пациент", "медицин", "история болезни",
	},
	"nlp_legal": {
		"nda", "confidential", "attorney-client", "privileged", "trade secret",
		"коммерческая тайна", "конфиденци", "служебная тайна", "адвокат",
	},
}

type NlpDLP struct {
	Action      string
	Classifiers []CompiledNlpClassifier
}

func (n NlpDLP) Active() bool {
	switch n.Action {
	case "audit", "mask", "deny":
		return true
	default:
		return false
	}
}

func (n NlpDLP) active() bool {
	return n.Active()
}

// NormalizeNlpDlpAction accepts "", audit, mask, deny.
func NormalizeNlpDlpAction(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "", nil
	case "audit":
		return "audit", nil
	case "mask":
		return "mask", nil
	case "deny":
		return "deny", nil
	default:
		return "", fmt.Errorf("nlp_dlp_action must be audit, mask, deny, or empty")
	}
}

type nlpSpan struct {
	start, end int
	kind       string
}

func scanNLP(text string, cfg NlpDLP) (kinds []string, masked string, deny bool) {
	if !cfg.active() || text == "" {
		return nil, text, false
	}
	if len(text) > maxNlpScan {
		text = text[:maxNlpScan]
	}
	low := strings.ToLower(text)
	var spans []nlpSpan
	addSpan := func(start, end int, kind string) {
		if start < 0 || end <= start || end > len(text) {
			return
		}
		spans = append(spans, nlpSpan{start, end, kind})
	}

	if loc := rePrivateKey.FindStringIndex(text); loc != nil {
		addSpan(loc[0], loc[1], "nlp_private_key")
	}

	seenKind := map[string]struct{}{}
	var order []string
	recordKind := func(kind string) {
		if _, ok := seenKind[kind]; ok {
			return
		}
		seenKind[kind] = struct{}{}
		order = append(order, kind)
	}

	for kind, keywords := range builtinNlpCategories {
		hits := 0
		for _, kw := range keywords {
			if kw == "" {
				continue
			}
			if matchNlpKeyword(low, text, kw, addSpan, kind) {
				hits++
			}
		}
		if hits > 0 {
			recordKind(kind)
		}
	}

	for _, rule := range cfg.Classifiers {
		hits := 0
		for _, kw := range rule.Keywords {
			if matchNlpKeyword(low, text, kw, addSpan, rule.Name) {
				hits++
			}
		}
		if hits >= rule.MinHits {
			recordKind(rule.Name)
		}
	}

	if len(order) == 0 {
		return nil, text, false
	}
	sort.Strings(order)
	if cfg.Action == "deny" {
		return order, text, true
	}
	if cfg.Action == "audit" {
		return order, text, false
	}
	// mask
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end > spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	var kept []nlpSpan
	end := -1
	for _, sp := range spans {
		if sp.start < end {
			continue
		}
		kept = append(kept, sp)
		end = sp.end
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, sp := range kept {
		b.WriteString(text[pos:sp.start])
		b.WriteString("***")
		pos = sp.end
	}
	b.WriteString(text[pos:])
	return order, b.String(), false
}

func matchNlpKeyword(low, orig, kw string, add func(int, int, string), kind string) bool {
	kw = strings.TrimSpace(strings.ToLower(kw))
	if kw == "" {
		return false
	}
	if strings.Contains(kw, " ") {
		idx := strings.Index(low, kw)
		if idx < 0 {
			return false
		}
		add(idx, idx+len(kw), kind)
		return true
	}
	start := 0
	found := false
	for {
		idx := strings.Index(low[start:], kw)
		if idx < 0 {
			break
		}
		idx += start
		if nlpWordBoundary(low, idx, len(kw)) {
			add(idx, idx+len(kw), kind)
			found = true
		}
		start = idx + len(kw)
		if start >= len(low) {
			break
		}
	}
	return found
}

func nlpWordBoundary(s string, start, length int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if isWordRune(r) {
			return false
		}
	}
	end := start + length
	if end < len(s) {
		r, _ := utf8.DecodeRuneInString(s[end:])
		if r != utf8.RuneError && isWordRune(r) {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-'
}

func mergeKinds(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := map[string]struct{}{}
	var out []string
	for _, k := range append(a, b...) {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
