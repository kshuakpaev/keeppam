package k8sproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNeedsNamespaceListFilter(t *testing.T) {
	allow := []string{"prod"}
	list := ParseAPIPath("GET", "/api/v1/namespaces", false)
	if ok, reason := NamespaceAllowed(allow, list); !ok || reason != "filter_namespaces" {
		t.Fatalf("ok=%v reason=%q", ok, reason)
	}
	if !NeedsNamespaceListFilter(allow, list) {
		t.Fatal("expected filter")
	}
	if NeedsNamespaceListFilter(nil, list) {
		t.Fatal("empty ACL should pass through")
	}
	watch := ParseAPIPath("GET", "/api/v1/namespaces", true)
	if ok, _ := NamespaceAllowed(allow, watch); ok {
		t.Fatal("watch cluster ns should deny")
	}
}

func TestFilterNamespaceListJSON(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"kind": "NamespaceList", "apiVersion": "v1",
		"items": []any{
			map[string]any{"metadata": map[string]any{"name": "prod"}},
			map[string]any{"metadata": map[string]any{"name": "kube-system"}},
			map[string]any{"metadata": map[string]any{"name": "other"}},
		},
	})
	got := FilterNamespaceListJSON(raw, []string{"prod", "kube-system"})
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	items, _ := m["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("len=%d %s", len(items), got)
	}
}

func TestSyntheticNamespaceList(t *testing.T) {
	raw := SyntheticNamespaceList([]string{"prod"}, false)
	if !strings.Contains(string(raw), `"name":"prod"`) {
		t.Fatal(string(raw))
	}
	tbl := SyntheticNamespaceList([]string{"prod"}, true)
	if !strings.Contains(string(tbl), `"kind":"Table"`) {
		t.Fatal(string(tbl))
	}
}

func TestRedactSecretJSON(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"kind": "Secret", "apiVersion": "v1",
		"metadata":   map[string]any{"name": "x"},
		"data":       map[string]any{"password": "c2VjcmV0"},
		"stringData": map[string]any{"token": "plain"},
	})
	got := RedactSecretJSON(raw)
	s := string(got)
	if strings.Contains(s, "c2VjcmV0") || strings.Contains(s, "plain") {
		t.Fatal(s)
	}
	if !strings.Contains(s, `"password":"***"`) {
		t.Fatal(s)
	}
}

func TestAPIPathAndSummarize(t *testing.T) {
	k, err := LookupKind("po", "")
	if err != nil || k.Resource != "pods" {
		t.Fatalf("%v %v", k, err)
	}
	p, err := APIPath(k, "prod", "web")
	if err != nil || p != "/api/v1/namespaces/prod/pods/web" {
		t.Fatal(p, err)
	}
	raw := []byte(`{"kind":"PodList","items":[{"kind":"Pod","metadata":{"name":"web","namespace":"prod","creationTimestamp":"2026-01-01T00:00:00Z"},"status":{"phase":"Running"}}]}`)
	items := SummarizeList(raw)
	if len(items) != 1 || items[0].Name != "web" || items[0].Status != "Running" {
		t.Fatalf("%+v", items)
	}
}
