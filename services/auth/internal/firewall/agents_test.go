package firewall

import "testing"

func TestQuorumReachable(t *testing.T) {
	ok, q := quorumReachable([]bool{true, false}, 1)
	if !ok || q != 1 {
		t.Fatalf("1 of 2 %+v", q)
	}
	ok, q = quorumReachable([]bool{true, false}, 2)
	if ok || q != 2 {
		t.Fatalf("need 2 %+v", q)
	}
	ok, q = quorumReachable([]bool{true, true}, 2)
	if !ok || q != 2 {
		t.Fatalf("2 of 2 %+v", q)
	}
}

func TestAgentsForAsset(t *testing.T) {
	agents := []loadedProbeAgent{
		{ProbeAgent: ProbeAgent{Name: "a", Segment: "dmz"}},
		{ProbeAgent: ProbeAgent{Name: "b", Segment: "office"}},
		{ProbeAgent: ProbeAgent{Name: "c", Segment: ""}},
	}
	if len(agentsForAsset(agents, "")) != 3 {
		t.Fatal("empty asset segment uses all")
	}
	got := agentsForAsset(agents, "dmz")
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Fatalf("%v", got)
	}
}
