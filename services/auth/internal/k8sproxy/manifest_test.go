package k8sproxy

import (
	"testing"
)

func TestParseManifestsYAMLAndJSON(t *testing.T) {
	docs, err := ParseManifests([]byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
  namespace: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`))
	if err != nil || len(docs) != 2 {
		t.Fatalf("docs=%d err=%v", len(docs), err)
	}
	_, kind, ns, name := ManifestIdentity(docs[0])
	if kind != "ConfigMap" || ns != "prod" || name != "a" {
		t.Fatalf("%s %s %s", kind, ns, name)
	}
	js, err := ParseManifests([]byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"}}`))
	if err != nil || len(js) != 1 {
		t.Fatal(err)
	}
}

func TestLookupKindFromGVK(t *testing.T) {
	k, err := LookupKindFromGVK("v1", "Pod")
	if err != nil || k.Resource != "pods" || k.Group != "" {
		t.Fatalf("%+v %v", k, err)
	}
	k, err = LookupKindFromGVK("apps/v1", "Deployment")
	if err != nil || k.Resource != "deployments" || k.Group != "apps" {
		t.Fatalf("%+v %v", k, err)
	}
	k, err = LookupKindFromGVK("apps/v1", "ReplicaSet")
	if err != nil || k.Resource != "replicasets" {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestWriteAllowed(t *testing.T) {
	if err := WriteAllowed(ParseAPIPath("POST", "/api/v1/namespaces/p/configmaps", false)); err != nil {
		t.Fatal(err)
	}
	if err := WriteAllowed(ParseAPIPath("DELETE", "/api/v1/namespaces/p/secrets/x", false)); err != nil {
		t.Fatal(err)
	}
	if err := WriteAllowed(ParseAPIPath("DELETE", "/api/v1/namespaces/p/secrets", false)); err == nil {
		t.Fatal("deletecollection should be denied")
	}
	if err := WriteAllowed(ParseAPIPath("POST", "/api/v1/namespaces/n/pods/p/exec", false)); err == nil {
		t.Fatal("exec should be denied on write path")
	}
	if err := WriteAllowed(ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/attach", false)); err == nil {
		t.Fatal("attach should be denied on write path")
	}
}

func TestSecretLooksRedacted(t *testing.T) {
	obj := map[string]any{
		"kind": "Secret",
		"data": map[string]any{"password": "***"},
	}
	if !SecretLooksRedacted(obj) {
		t.Fatal("expected redacted")
	}
	obj["data"] = map[string]any{"password": "c2VjcmV0"}
	if SecretLooksRedacted(obj) {
		t.Fatal("real secret")
	}
}

func TestStripForCreate(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{"phase": "Running"},
		"metadata": map[string]any{
			"name": "x", "resourceVersion": "9", "uid": "u", "managedFields": []any{1},
		},
	}
	StripForCreate(obj)
	if _, ok := obj["status"]; ok {
		t.Fatal("status")
	}
	md := obj["metadata"].(map[string]any)
	if _, ok := md["resourceVersion"]; ok {
		t.Fatal("rv")
	}
	if md["name"] != "x" {
		t.Fatal(md)
	}
}

func TestSplitAPIVersion(t *testing.T) {
	g, v := SplitAPIVersion("apps/v1")
	if g != "apps" || v != "v1" {
		t.Fatalf("%s %s", g, v)
	}
	g, v = SplitAPIVersion("v1")
	if g != "" || v != "v1" {
		t.Fatalf("%s %s", g, v)
	}
}
