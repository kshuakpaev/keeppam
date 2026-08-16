package k8sproxy

import (
	"strings"
	"testing"
)

func TestSanitizePFPath(t *testing.T) {
	if got := sanitizePFPath(""); got != "/" {
		t.Fatal(got)
	}
	if got := sanitizePFPath("healthz"); got != "/healthz" {
		t.Fatal(got)
	}
	if got := sanitizePFPath("/x\r\nHost: evil"); got != "/x" {
		t.Fatal(got)
	}
	if got := sanitizePFPath("/metrics?foo=1"); got != "/metrics?foo=1" {
		t.Fatal(got)
	}
}

func TestBuildAndParseHTTP(t *testing.T) {
	req := buildPFHTTPRequest("GET", "/healthz", 8080, nil)
	if !strings.Contains(string(req), "GET /healthz HTTP/1.1") {
		t.Fatalf("%s", req)
	}
	if strings.Contains(string(req), "\r\n\r\n\r\n") {
		t.Fatal("extra blank")
	}
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nSet-Cookie: a=b\r\n\r\nok")
	res, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.Body != "ok" {
		t.Fatalf("%+v", res)
	}
	if res.Headers["Set-Cookie"] != "(redacted)" {
		t.Fatalf("cookie: %+v", res.Headers)
	}
}

func TestHTTPResponseComplete(t *testing.T) {
	partial := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab")
	if httpResponseComplete(partial) {
		t.Fatal("partial")
	}
	full := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if !httpResponseComplete(full) {
		t.Fatal("full")
	}
}

func TestAllowPodSubresource(t *testing.T) {
	exec := ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/exec", false)
	if err := allowPodSubresource(exec, "exec"); err != nil {
		t.Fatal(err)
	}
	if err := allowPodSubresource(exec, "attach"); err == nil {
		t.Fatal("mismatch")
	}
	att := ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/attach", false)
	if !att.Denied() {
		t.Fatal("attach denied on :16443")
	}
	if err := allowPodSubresource(att, "attach"); err != nil {
		t.Fatal(err)
	}
	pf := ParseAPIPath("GET", "/api/v1/namespaces/n/pods/p/portforward", false)
	if !pf.Denied() {
		t.Fatal("portforward denied on :16443")
	}
	if err := allowPodSubresource(pf, "portforward"); err != nil {
		t.Fatal(err)
	}
	if err := WriteAllowed(pf); err == nil {
		t.Fatal("write path still denies pf")
	}
}
