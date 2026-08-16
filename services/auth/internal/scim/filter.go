package scim

import (
	"strconv"
	"strings"
)

type EqFilter struct {
	Attr  string
	Value string
}

// ParseEqFilter understands the subset Entra/Okta send: `attr eq "value"`.
func ParseEqFilter(raw string) (EqFilter, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return EqFilter{}, false
	}
	low := strings.ToLower(s)
	idx := strings.Index(low, " eq ")
	if idx < 1 {
		return EqFilter{}, false
	}
	attr := strings.TrimSpace(s[:idx])
	rest := strings.TrimSpace(s[idx+4:])
	if attr == "" || rest == "" {
		return EqFilter{}, false
	}
	if unq, err := strconv.Unquote(rest); err == nil {
		rest = unq
	} else {
		rest = strings.Trim(rest, `"'`)
	}
	return EqFilter{Attr: strings.ToLower(attr), Value: rest}, true
}

func ClampPage(startIndex, count int) (offset, limit int) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = 100
	}
	if count > 200 {
		count = 200
	}
	return startIndex - 1, count
}
