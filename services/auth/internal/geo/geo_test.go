package geo

import "testing"

func TestNormalizeRole(t *testing.T) {
	if NormalizeRole("DR") != RoleStandby {
		t.Fatal(NormalizeRole("DR"))
	}
	if NormalizeRole("primary") != RolePrimary {
		t.Fatal()
	}
	cfg := Config{Role: RoleStandby, SiteID: "b"}
	if cfg.AllowsSessionWrites() {
		t.Fatal("standby must fence")
	}
	if FenceError(cfg) == nil {
		t.Fatal("expected fence")
	}
	if FenceError(Config{Role: RolePrimary}) != nil {
		t.Fatal()
	}
}
