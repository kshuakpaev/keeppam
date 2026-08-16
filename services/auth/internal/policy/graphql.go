package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxGraphQLFields = 32

// ExtractGraphQLFields returns top-level selection names of the operation.
// ok=false means the body is not a GraphQL request.
func ExtractGraphQLFields(contentType string, body []byte) (fields []string, ok bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, false
	}
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case ct == "application/graphql" || strings.HasPrefix(ct, "application/graphql"):
		return parseGraphQLDocument("", string(body))
	case strings.Contains(ct, "json") || (len(body) > 0 && (body[0] == '{' || body[0] == '[')):
		return extractGraphQLJSON(body)
	default:
		return nil, false
	}
}

func extractGraphQLJSON(body []byte) ([]string, bool) {
	if len(body) > 0 && body[0] == '[' {
		var batch []json.RawMessage
		if json.Unmarshal(body, &batch) != nil || len(batch) == 0 {
			return nil, false
		}
		var all []string
		anyOK := false
		for _, item := range batch {
			f, ok := extractGraphQLJSON(item)
			if !ok {
				continue
			}
			anyOK = true
			all = append(all, f...)
			if len(all) >= maxGraphQLFields {
				break
			}
		}
		if !anyOK {
			return nil, false
		}
		return uniqFields(all), true
	}
	var env struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName"`
	}
	if json.Unmarshal(body, &env) != nil || strings.TrimSpace(env.Query) == "" {
		return nil, false
	}
	return parseGraphQLDocument(env.OperationName, env.Query)
}

func parseGraphQLDocument(opName, src string) ([]string, bool) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, false
	}
	p := gqlParser{s: src}
	fields, ok := p.document(strings.TrimSpace(opName))
	if !ok {
		return nil, false
	}
	return uniqFields(fields), true
}

func uniqFields(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range in {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		k := strings.ToLower(f)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
		if len(out) >= maxGraphQLFields {
			break
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

type gqlParser struct {
	s string
	i int
}

func (p *gqlParser) document(wantOp string) ([]string, bool) {
	var (
		anon    []string
		named   []string
		anonOK  bool
		namedOK bool
	)
	for {
		p.skip()
		if p.i >= len(p.s) {
			break
		}
		if p.peek() == '{' {
			f, ok := p.selectionSet()
			if !ok {
				return nil, false
			}
			if !anonOK {
				anon, anonOK = f, true
			}
			continue
		}
		kw := p.ident()
		if kw == "" {
			p.i++
			continue
		}
		switch strings.ToLower(kw) {
		case "fragment":
			p.skip()
			_ = p.ident()
			p.skip()
			if strings.EqualFold(p.ident(), "on") {
				p.skip()
				_ = p.ident()
			}
			p.skip()
			if !p.skipBalanced('{', '}') {
				return nil, false
			}
		case "query", "mutation", "subscription":
			p.skip()
			name := ""
			if id := p.ident(); id != "" {
				name = id
			}
			p.skip()
			if p.peek() == '(' {
				if !p.skipBalanced('(', ')') {
					return nil, false
				}
			}
			for {
				p.skip()
				if p.peek() != '@' {
					break
				}
				p.i++
				_ = p.ident()
				p.skip()
				if p.peek() == '(' {
					if !p.skipBalanced('(', ')') {
						return nil, false
					}
				}
			}
			p.skip()
			f, ok := p.selectionSet()
			if !ok {
				return nil, false
			}
			if wantOp != "" && name != "" && name == wantOp {
				return f, true
			}
			if name == "" && !anonOK {
				anon, anonOK = f, true
			}
			if name != "" && !namedOK {
				named, namedOK = f, true
			}
		default:
			// unknown token — stop rather than mis-parse
			return nil, false
		}
	}
	if wantOp != "" {
		if namedOK {
			return named, true
		}
		return nil, false
	}
	if anonOK {
		return anon, true
	}
	if namedOK {
		return named, true
	}
	return nil, false
}

func (p *gqlParser) selectionSet() ([]string, bool) {
	p.skip()
	if p.peek() != '{' {
		return nil, false
	}
	p.i++
	var fields []string
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, false
		}
		if p.peek() == '}' {
			p.i++
			return fields, true
		}
		if p.peek() == '.' && p.i+2 < len(p.s) && p.s[p.i:p.i+3] == "..." {
			p.i += 3
			p.skip()
			if strings.EqualFold(p.ident(), "on") {
				p.skip()
				_ = p.ident()
			} else {
				// fragment spread name already consumed if ident()
			}
			p.skip()
			if p.peek() == '{' {
				if !p.skipBalanced('{', '}') {
					return nil, false
				}
			}
			continue
		}
		name := p.ident()
		if name == "" {
			return nil, false
		}
		p.skip()
		field := name
		if p.peek() == ':' {
			p.i++
			p.skip()
			real := p.ident()
			if real == "" {
				return nil, false
			}
			field = real
		}
		p.skip()
		if p.peek() == '(' {
			if !p.skipBalanced('(', ')') {
				return nil, false
			}
		}
		for {
			p.skip()
			if p.peek() != '@' {
				break
			}
			p.i++
			_ = p.ident()
			p.skip()
			if p.peek() == '(' {
				if !p.skipBalanced('(', ')') {
					return nil, false
				}
			}
		}
		p.skip()
		if p.peek() == '{' {
			if !p.skipBalanced('{', '}') {
				return nil, false
			}
		}
		fields = append(fields, field)
		if len(fields) >= maxGraphQLFields {
			p.skipUntilSelEnd()
			return fields, true
		}
	}
}

func (p *gqlParser) skipUntilSelEnd() {
	depth := 1
	for p.i < len(p.s) && depth > 0 {
		p.skip()
		switch p.peek() {
		case '{':
			depth++
			p.i++
		case '}':
			depth--
			p.i++
		case '"', '\'':
			p.skipString()
		default:
			if p.peek() == 0 {
				return
			}
			p.i++
		}
	}
}

func (p *gqlParser) ident() string {
	p.skip()
	if p.i >= len(p.s) {
		return ""
	}
	r, w := utf8.DecodeRuneInString(p.s[p.i:])
	if r != '_' && !unicode.IsLetter(r) {
		return ""
	}
	start := p.i
	p.i += w
	for p.i < len(p.s) {
		r, w = utf8.DecodeRuneInString(p.s[p.i:])
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			break
		}
		p.i += w
	}
	return p.s[start:p.i]
}

func (p *gqlParser) skip() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r', ',':
			p.i++
		case '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case '"':
			if strings.HasPrefix(p.s[p.i:], `"""`) {
				p.i += 3
				if j := strings.Index(p.s[p.i:], `"""`); j >= 0 {
					p.i += j + 3
				} else {
					p.i = len(p.s)
				}
				continue
			}
			p.skipString()
		default:
			return
		}
	}
}

func (p *gqlParser) skipString() {
	if p.peek() != '"' {
		return
	}
	p.i++
	for p.i < len(p.s) {
		if p.s[p.i] == '\\' {
			p.i += 2
			continue
		}
		if p.s[p.i] == '"' {
			p.i++
			return
		}
		p.i++
	}
}

func (p *gqlParser) skipBalanced(open, close byte) bool {
	if p.peek() != rune(open) {
		return false
	}
	depth := 0
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '"':
			p.skipString()
			continue
		case '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
			continue
		case open:
			depth++
		case close:
			depth--
			p.i++
			if depth == 0 {
				return true
			}
			continue
		}
		p.i++
	}
	return false
}

func (p *gqlParser) peek() rune {
	if p.i >= len(p.s) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(p.s[p.i:])
	return r
}
