package k8sproxy

import (
	"encoding/json"
	"strings"
)

func FilterNamespaceListJSON(raw []byte, allowed []string) []byte {
	allowed = NormalizeNamespaces(allowed)
	if len(allowed) == 0 || len(raw) == 0 {
		return raw
	}
	set := map[string]struct{}{}
	for _, n := range allowed {
		set[n] = struct{}{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	kind, _ := m["kind"].(string)
	switch kind {
	case "NamespaceList":
		m["items"] = filterObjList(m["items"], set)
	case "Table":
		m["rows"] = filterTableRows(m["rows"], set)
	default:
		return raw
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func SyntheticNamespaceList(allowed []string, asTable bool) []byte {
	allowed = NormalizeNamespaces(allowed)
	if asTable {
		rows := make([]any, 0, len(allowed))
		for _, n := range allowed {
			rows = append(rows, map[string]any{
				"cells": []any{n, "Active", ""},
				"object": map[string]any{
					"kind":       "PartialObjectMetadata",
					"apiVersion": "meta.k8s.io/v1",
					"metadata":   map[string]any{"name": n},
				},
			})
		}
		raw, _ := json.Marshal(map[string]any{
			"kind":       "Table",
			"apiVersion": "meta.k8s.io/v1",
			"metadata":   map[string]any{},
			"columnDefinitions": []any{
				map[string]any{"name": "Name", "type": "string", "format": "name", "priority": 0},
				map[string]any{"name": "Status", "type": "string", "priority": 0},
				map[string]any{"name": "Age", "type": "string", "priority": 0},
			},
			"rows": rows,
		})
		return raw
	}
	items := make([]any, 0, len(allowed))
	for _, n := range allowed {
		items = append(items, map[string]any{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata":   map[string]any{"name": n},
			"status":     map[string]any{"phase": "Active"},
		})
	}
	raw, _ := json.Marshal(map[string]any{
		"kind":       "NamespaceList",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"items":      items,
	})
	return raw
}

func wantsTable(accept string) bool {
	return strings.Contains(strings.ToLower(accept), "as=table")
}

func filterObjList(items any, set map[string]struct{}) []any {
	arr, _ := items.([]any)
	var out []any
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		name := objectName(m)
		if _, ok := set[strings.ToLower(name)]; ok {
			out = append(out, it)
		}
	}
	if out == nil {
		return []any{}
	}
	return out
}

func filterTableRows(rows any, set map[string]struct{}) []any {
	arr, _ := rows.([]any)
	var out []any
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		name := ""
		if obj, ok := m["object"].(map[string]any); ok {
			name = objectName(obj)
		}
		if name == "" {
			if cells, ok := m["cells"].([]any); ok && len(cells) > 0 {
				name, _ = cells[0].(string)
			}
		}
		if _, ok := set[strings.ToLower(name)]; ok {
			out = append(out, it)
		}
	}
	if out == nil {
		return []any{}
	}
	return out
}

func objectName(m map[string]any) string {
	if md, ok := m["metadata"].(map[string]any); ok {
		if n, ok := md["name"].(string); ok {
			return n
		}
	}
	return ""
}

func RedactSecretJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	redactSecretValue(m)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func redactSecretValue(m map[string]any) {
	kind, _ := m["kind"].(string)
	switch kind {
	case "Secret":
		redactSecretData(m)
	case "SecretList":
		items, _ := m["items"].([]any)
		for _, it := range items {
			if mm, ok := it.(map[string]any); ok {
				redactSecretData(mm)
			}
		}
	}
}

func redactSecretData(m map[string]any) {
	for _, key := range []string{"data", "stringData"} {
		data, ok := m[key].(map[string]any)
		if !ok {
			continue
		}
		for k := range data {
			data[k] = "***"
		}
	}
}
