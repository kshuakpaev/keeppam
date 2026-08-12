package policy

import "testing"

func TestIPAllowed(t *testing.T) {
	if !ipAllowed(nil, "10.1.2.3") {
		t.Fatal("empty cidrs should allow")
	}
	if !ipAllowed([]string{"10.0.0.0/8"}, "10.1.2.3") {
		t.Fatal("expected 10.1.2.3 in 10/8")
	}
	if ipAllowed([]string{"10.0.0.0/8"}, "192.168.1.1") {
		t.Fatal("192.168 should be denied")
	}
	if !ipAllowed([]string{"192.168.1.10"}, "192.168.1.10") {
		t.Fatal("exact IP")
	}
	if !ipAllowed([]string{"10.0.0.0/8"}, "10.1.2.3:443") {
		t.Fatal("host:port should parse")
	}
}
