package tagpath

import (
	"sort"
	"strings"
)

// Normalize lowercases, collapses slashes, dedups and sorts.
// " Prod//Linux/ " → ["prod/linux"]. Invalid paths ("..", >8 segments) are dropped.
func Normalize(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range in {
		t = Canonical(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}

// Canonical lowercases and collapses hierarchy.
func Canonical(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return ""
	}
	t = strings.ReplaceAll(t, "\\", "/")
	var segs []string
	for _, p := range strings.Split(t, "/") {
		p = strings.TrimSpace(p)
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return ""
		}
		segs = append(segs, p)
	}
	if len(segs) == 0 || len(segs) > 8 {
		return ""
	}
	return strings.Join(segs, "/")
}

// ExpandAncestors adds parent paths: prod/linux/web → prod, prod/linux, prod/linux/web.
// Child implies parent. Parent does not imply child.
func ExpandAncestors(tags []string) []string {
	tags = Normalize(tags)
	seen := map[string]struct{}{}
	var out []string
	add := func(t string) {
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, t := range tags {
		parts := strings.Split(t, "/")
		acc := ""
		for i, p := range parts {
			if i == 0 {
				acc = p
			} else {
				acc += "/" + p
			}
			add(acc)
		}
	}
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}
