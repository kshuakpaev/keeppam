package k8sproxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestNamespaceAllowed(t *testing.T) {
	allow := []string{"Prod", "kube-system"}
	cases := []struct {
		method, path string
		ok           bool
		reason       string
	}{
		{"GET", "/api", true, ""},
		{"GET", "/apis", true, ""},
		{"GET", "/version", true, ""},
		{"GET", "/api/v1", true, ""},
		{"GET", "/api/v1/namespaces/prod/pods", true, ""},
		{"GET", "/api/v1/namespaces/prod/pods/web", true, ""},
		{"GET", "/apis/apps/v1/namespaces/kube-system/deployments", true, ""},
		{"GET", "/api/v1/namespaces/prod", true, ""},
		{"GET", "/api/v1/namespaces/other/pods", false, "namespace_acl"},
		{"GET", "/api/v1/namespaces/other", false, "namespace_acl"},
		{"GET", "/api/v1/pods", false, "cluster_scope_denied"},
		{"GET", "/api/v1/namespaces", true, "filter_namespaces"},
		{"GET", "/api/v1/nodes", false, "cluster_scope_denied"},
		{"POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", true, ""},
	}
	for _, tc := range cases {
		c := ParseAPIPath(tc.method, tc.path, false)
		ok, reason := NamespaceAllowed(allow, c)
		if ok != tc.ok || reason != tc.reason {
			t.Fatalf("%s %s call=%+v ok=%v reason=%q want ok=%v reason=%q",
				tc.method, tc.path, c, ok, reason, tc.ok, tc.reason)
		}
	}
	ok, _ := NamespaceAllowed(nil, ParseAPIPath("GET", "/api/v1/nodes", false))
	if !ok {
		t.Fatal("empty allowlist should permit cluster scope")
	}
}

func TestValidateNamespaces(t *testing.T) {
	got, err := ValidateNamespaces([]string{" Prod ", "prod", "kube-system"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "prod" || got[1] != "kube-system" {
		t.Fatalf("%v", got)
	}
	if _, err := ValidateNamespaces([]string{"BAD_NS"}); err == nil {
		t.Fatal("expected invalid")
	}
}

func TestImpersonateUserAndHeaders(t *testing.T) {
	if ImpersonateUser("", "alice") != "keeppam:alice" {
		t.Fatal(ImpersonateUser("", "alice"))
	}
	if ImpersonateUser("-", "alice") != "alice" {
		t.Fatal("raw username")
	}
	groups := ImpersonateGroups([]string{"operator", " operator ", "admin"}, []string{"dba"})
	if len(groups) < 4 || groups[0] != "system:authenticated" {
		t.Fatalf("%v", groups)
	}
	h := make(http.Header)
	ApplyImpersonate(h, "keeppam:alice", groups, "uid-1")
	if h.Get("Impersonate-User") != "keeppam:alice" {
		t.Fatal(h.Get("Impersonate-User"))
	}
	if h.Get("Impersonate-Extra-keeppam-uid") != "uid-1" {
		t.Fatal(h.Get("Impersonate-Extra-keeppam-uid"))
	}
	got := h.Values("Impersonate-Group")
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "keeppam:role:operator") || !strings.Contains(joined, "keeppam:group:dba") {
		t.Fatalf("groups %v", got)
	}
}
