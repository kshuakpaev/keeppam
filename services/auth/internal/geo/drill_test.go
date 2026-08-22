package geo

import (
	"context"
	"testing"
)

func TestRunDrillStandby(t *testing.T) {
	cfg := Config{SiteID: "b", Role: RoleStandby}
	st := Status{AllowsWrites: false, ReplicaProbe: "skipped"}
	rec, _ := RecordingsStatusOf(RecordingsConfig{Mode: "rsync", RsyncTarget: "x:/y"}, nil)
	rep := RunDrill(cfg, st, rec, WitnessStatus{Mode: "off"})
	if !rep.OK {
		t.Fatalf("%#v", rep)
	}
	for _, c := range rep.Checks {
		if c.Name == "standby_fence" && c.Status != "pass" {
			t.Fatalf("%#v", c)
		}
	}
}

func TestCutoverCheckSkip(t *testing.T) {
	c := CutoverCheck(context.Background(), "", "a", RolePrimary)
	if c.Status != "skip" {
		t.Fatal(c)
	}
}
