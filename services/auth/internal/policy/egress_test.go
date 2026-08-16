package policy

import (
	"net"
	"testing"
)

func TestValidateEgress(t *testing.T) {
	got, err := ValidateEgress([]string{
		" 10.1.2.0/24:5432 ",
		"db.prod.local:5432",
		"192.168.10.5",
		"10.1.2.0/24:5432",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if _, err := ValidateEgress([]string{"127.0.0.1:80"}); err == nil {
		t.Fatal("loopback")
	}
	if _, err := ValidateEgress([]string{"localhost:80"}); err == nil {
		t.Fatal("localhost")
	}
	if _, err := ValidateEgress([]string{"169.254.169.254:80"}); err == nil {
		t.Fatal("link-local")
	}
	if _, err := ValidateEgress([]string{"not a host!!"}); err == nil {
		t.Fatal("junk")
	}
	if _, err := ValidateEgress([]string{"0.0.0.0/0:443"}); err != nil {
		t.Fatalf("any dest cidr should be allowed in the list: %v", err)
	}
}

func TestMatchEgress(t *testing.T) {
	rules := []string{"10.1.2.0/24:5432", "db.prod.local:5432", "192.168.10.5"}
	if !MatchEgress(rules, "10.1.2.9", 5432) {
		t.Fatal("cidr+port")
	}
	if MatchEgress(rules, "10.1.2.9", 22) {
		t.Fatal("wrong port")
	}
	if !MatchEgress(rules, "192.168.10.5", 443) {
		t.Fatal("ip any port")
	}
	if !MatchEgress(rules, "DB.PROD.LOCAL", 5432) {
		t.Fatal("hostname")
	}
	if MatchEgress(rules, "other.local", 5432) {
		t.Fatal("other host")
	}
	if MatchEgress(nil, "10.1.2.9", 5432) {
		t.Fatal("empty deny")
	}
	lookupIPFn = func(host string) ([]net.IP, error) {
		if host == "pg.internal" {
			return []net.IP{net.ParseIP("10.1.2.40")}, nil
		}
		return nil, nil
	}
	t.Cleanup(func() { lookupIPFn = net.LookupIP })
	if !MatchEgress([]string{"10.1.2.0/24:5432"}, "pg.internal", 5432) {
		t.Fatal("resolved hostname vs cidr")
	}
}

func TestAllowSSHEgress(t *testing.T) {
	if _, deny := AllowSSHEgress(Snapshot{}, "10.1.2.3", 5432); !deny {
		t.Fatal("empty list")
	}
	sn := Snapshot{AllowedEgress: []string{"10.1.2.0/24:5432"}}
	if _, deny := AllowSSHEgress(sn, "10.1.2.3", 5432); deny {
		t.Fatal("allow")
	}
	if _, deny := AllowSSHEgress(sn, "10.9.9.9", 5432); !deny {
		t.Fatal("miss")
	}
	if _, deny := AllowSSHEgress(Snapshot{BreakGlass: true}, "10.9.9.9", 5432); deny {
		t.Fatal("break-glass")
	}
}

func TestParseIPv6Egress(t *testing.T) {
	got, err := ValidateEgress([]string{"[2001:db8::1]:443", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if !MatchEgress(got, "2001:db8::1", 443) {
		t.Fatal("v6 host")
	}
	if !MatchEgress(got, "2001:db8::aa", 22) {
		t.Fatal("v6 cidr any port")
	}
}
