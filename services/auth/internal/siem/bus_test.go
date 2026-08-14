package siem

import "testing"

func TestSplitBrokers(t *testing.T) {
	got := splitBrokers(" kafka:9092,  10.0.0.2:9092 , ")
	if len(got) != 2 || got[0] != "kafka:9092" || got[1] != "10.0.0.2:9092" {
		t.Fatalf("%v", got)
	}
	if len(splitBrokers("")) != 0 || len(splitBrokers(" , , ")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestValidTransport(t *testing.T) {
	for _, tr := range []string{"off", "syslog_udp", "syslog_tcp", "webhook", "kafka", "nats"} {
		if !validTransport(tr) {
			t.Fatalf("want valid %s", tr)
		}
	}
	if validTransport("rabbit") {
		t.Fatal("rabbit")
	}
}
