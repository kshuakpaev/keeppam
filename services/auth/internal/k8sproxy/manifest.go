package k8sproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseManifests(raw []byte) ([]map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}
	if raw[0] == '{' || raw[0] == '[' {
		if raw[0] == '[' {
			var arr []map[string]any
			if err := json.Unmarshal(raw, &arr); err != nil {
				return nil, fmt.Errorf("invalid json list: %w", err)
			}
			return arr, nil
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("invalid json: %w", err)
		}
		return []map[string]any{obj}, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var out []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid yaml: %w", err)
		}
		if len(doc) == 0 {
			continue
		}
		out = append(out, doc)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}
	return out, nil
}

func ManifestIdentity(obj map[string]any) (apiVersion, kind, ns, name string) {
	apiVersion = str(obj["apiVersion"])
	kind = str(obj["kind"])
	if md, ok := obj["metadata"].(map[string]any); ok {
		ns = str(md["namespace"])
		name = str(md["name"])
	}
	return apiVersion, kind, ns, name
}

func StripForCreate(obj map[string]any) {
	delete(obj, "status")
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		return
	}
	for _, k := range []string{"managedFields", "resourceVersion", "uid", "generation", "creationTimestamp", "selfLink"} {
		delete(md, k)
	}
}

func SetResourceVersion(obj map[string]any, rv string) {
	delete(obj, "status")
	md, _ := obj["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		obj["metadata"] = md
	}
	delete(md, "managedFields")
	if strings.TrimSpace(rv) != "" {
		md["resourceVersion"] = rv
	}
}

func ObjectResourceVersion(raw []byte) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	md, _ := m["metadata"].(map[string]any)
	return str(md["resourceVersion"])
}

func SecretLooksRedacted(obj map[string]any) bool {
	if str(obj["kind"]) != "Secret" {
		return false
	}
	for _, key := range []string{"data", "stringData"} {
		data, _ := obj[key].(map[string]any)
		for _, v := range data {
			if s, ok := v.(string); ok && s == "***" {
				return true
			}
		}
	}
	return false
}
