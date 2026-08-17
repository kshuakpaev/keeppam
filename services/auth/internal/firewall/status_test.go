package firewall

import (
	"testing"
	"time"
)

func TestStatusGaps(t *testing.T) {
	gaps := assetGaps(AssetStatus{Address: "10.0.0.1"}, false)
	if len(gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %v", gaps)
	}
	gaps = assetGaps(AssetStatus{Address: "10.0.0.1", FirewallAppliedAt: ptrTime()}, true)
	if len(gaps) != 0 {
		t.Fatalf("expected none, got %v", gaps)
	}
	gaps = assetGaps(AssetStatus{Address: "host.example.com"}, true)
	if len(gaps) != 2 {
		t.Fatalf("hostname gaps %v", gaps)
	}
	reach := true
	gaps = assetGaps(AssetStatus{Address: "10.0.0.1", FirewallAppliedAt: ptrTime(), FirewallProbeReachable: &reach}, true)
	if len(gaps) != 1 || gaps[0] != "probe_reachable" {
		t.Fatalf("probe gap %v", gaps)
	}
}

func ptrTime() *time.Time {
	t := time.Now()
	return &t
}
