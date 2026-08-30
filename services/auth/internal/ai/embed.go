package ai

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

const embedDim = 64

// synonym groups expand NL queries so "удаление схемы" hits DROP TABLE.
var synonymGroups = [][]string{
	{"drop", "удален", "удаление", "schema", "схем", "таблиц", "table", "database"},
	{"salary", "зарплат", "оклад", "compensation", "вознагражд"},
	{"password", "парол", "credential", "секрет", "secret"},
	{"dump", "дамп", "backup", "pg_dump", "mysqldump"},
	{"notepad", "блокнот", "notepad.exe"},
	{"rm", "удалить", "destructive", "mkfs"},
}

func tokenize(s string) []string {
	s = strings.ToLower(s)
	var b strings.Builder
	var out []string
	flush := func() {
		t := b.String()
		b.Reset()
		if t == "" {
			return
		}
		out = append(out, t)
		for _, g := range synonymGroups {
			hit := false
			for _, w := range g {
				if t == w || strings.Contains(t, w) || strings.Contains(w, t) {
					hit = true
					break
				}
			}
			if hit {
				out = append(out, g...)
			}
		}
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// HashEmbed is a deterministic bag-of-words vector (no GPU). Used by mock runtime and as fallback.
func HashEmbed(text string) []float32 {
	vec := make([]float32, embedDim)
	toks := tokenize(text)
	if len(toks) == 0 {
		return vec
	}
	for _, t := range toks {
		h := fnv.New32a()
		_, _ = h.Write([]byte(t))
		idx := int(h.Sum32() % uint32(embedDim))
		vec[idx] += 1
	}
	var norm float64
	for _, v := range vec {
		norm += float64(v) * float64(v)
	}
	norm = math.Sqrt(norm)
	if norm <= 0 {
		return vec
	}
	for i := range vec {
		vec[i] = float32(float64(vec[i]) / norm)
	}
	return vec
}

func cosine(a, b []float32) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na <= 1e-12 || nb <= 1e-12 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
