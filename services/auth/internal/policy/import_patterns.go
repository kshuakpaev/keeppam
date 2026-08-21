package policy

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const MaxImportPatterns = 10000

// ParsePatternList parses txt / csv / json command lists for JEA import (T-42).
// Lines starting with # are comments. Empty lines skipped.
func ParsePatternList(data []byte, filenameOrHint string) ([]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("file must be UTF-8")
	}
	hint := strings.ToLower(strings.TrimSpace(filenameOrHint))
	trim := bytes.TrimSpace(data)
	switch {
	case strings.HasSuffix(hint, ".json") || (len(trim) > 0 && (trim[0] == '{' || trim[0] == '[')):
		return parsePatternJSON(trim)
	case strings.HasSuffix(hint, ".csv"):
		return parsePatternCSV(trim)
	default:
		// Heuristic: if looks like CSV with commas on first line and header-ish
		first := string(bytes.SplitN(trim, []byte("\n"), 2)[0])
		if strings.Contains(first, ",") && looksCSVHeader(first) {
			return parsePatternCSV(trim)
		}
		return parsePatternTXT(trim)
	}
}

func parsePatternTXT(data []byte) ([]string, error) {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// allow "pattern, comment" as single pattern only when no CSV mode
		out = append(out, line)
		if len(out) > MaxImportPatterns {
			return nil, fmt.Errorf("too many patterns (max %d)", MaxImportPatterns)
		}
	}
	return normalizePatterns(out), nil
}

func parsePatternCSV(data []byte) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}
	col := 0
	start := 0
	if len(rows) > 0 && looksCSVHeader(strings.Join(rows[0], ",")) {
		for i, h := range rows[0] {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "pattern" || h == "command" || h == "cmd" || h == "glob" {
				col = i
				break
			}
		}
		start = 1
	}
	var out []string
	for _, row := range rows[start:] {
		if col >= len(row) {
			continue
		}
		p := strings.TrimSpace(row[col])
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		out = append(out, p)
		if len(out) > MaxImportPatterns {
			return nil, fmt.Errorf("too many patterns (max %d)", MaxImportPatterns)
		}
	}
	return normalizePatterns(out), nil
}

func looksCSVHeader(line string) bool {
	low := strings.ToLower(line)
	return strings.Contains(low, "pattern") || strings.Contains(low, "command") || strings.Contains(low, "glob")
}

func parsePatternJSON(data []byte) ([]string, error) {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) > MaxImportPatterns {
			return nil, fmt.Errorf("too many patterns (max %d)", MaxImportPatterns)
		}
		return normalizePatterns(arr), nil
	}
	var obj struct {
		Patterns []string `json:"patterns"`
		Commands []string `json:"commands"`
		List     []string `json:"list"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("json: expected array or {patterns|commands|list}")
	}
	arr = obj.Patterns
	if len(arr) == 0 {
		arr = obj.Commands
	}
	if len(arr) == 0 {
		arr = obj.List
	}
	if len(arr) > MaxImportPatterns {
		return nil, fmt.Errorf("too many patterns (max %d)", MaxImportPatterns)
	}
	return normalizePatterns(arr), nil
}

// ImportPackResult is returned by ImportCommandPackPatterns.
type ImportPackResult struct {
	Pack    CommandPack `json:"pack"`
	Added   int         `json:"added"`
	Total   int         `json:"total"`
	Merged  bool        `json:"merged"`
	Skipped int         `json:"skipped,omitempty"`
}
