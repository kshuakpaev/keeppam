package ueba

import (
	"strings"
	"testing"
)

func TestParseHostNetIPv4(t *testing.T) {
	h, n, ok := ParseHostNet("10.1.2.9")
	if !ok || h != "10.1.2.9" || n != "10.1.2.0/24" {
		t.Fatalf("%s %s %v", h, n, ok)
	}
	h2, n2, ok := ParseHostNet("10.1.2.9:443")
	if !ok || h2 != h || n2 != n {
		t.Fatalf("port strip %s %s", h2, n2)
	}
}

func TestParseHostNetIPv6(t *testing.T) {
	_, n, ok := ParseHostNet("2001:db8::1")
	if !ok || !strings.HasSuffix(n, "/64") {
		t.Fatalf("net=%s ok=%v", n, ok)
	}
}

func TestNewIPSubnet(t *testing.T) {
	if NewIP(2, false) {
		t.Fatal("cold start")
	}
	if !NewIP(3, false) || NewIP(3, true) {
		t.Fatal("host")
	}
	if !NewSubnet(3, false) || NewSubnet(3, true) {
		t.Fatal("net")
	}
}
