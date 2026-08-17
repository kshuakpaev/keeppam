package castindex

import (
	"testing"

	"github.com/keeppam/auth/internal/policy"
)

func TestApplyContentDLPIndex(t *testing.T) {
	denyDLP := policy.ContentDLP{Action: "deny"}
	line, skip, st := applyContentDLP(denyDLP, "user@example.com logged in")
	if !skip || st == nil || st.denied != 1 {
		t.Fatalf("deny %+v skip=%v", st, skip)
	}
	maskDLP := policy.ContentDLP{Action: "mask"}
	line, skip, st = applyContentDLP(maskDLP, "card 4111111111111111")
	if skip || line == "" || st == nil || st.masked != 1 {
		t.Fatalf("mask %q %+v", line, st)
	}
	line, skip, st = applyContentDLP(policy.ContentDLP{}, "user@example.com")
	if skip || line != "user@example.com" || st != nil {
		t.Fatalf("off %q", line)
	}
}

func TestDlpPayload(t *testing.T) {
	total := &outputPIIStats{
		masked: 2,
		kinds:  map[string]struct{}{"email": {}, "pan": {}},
	}
	ev := dlpPayload(total, "ssh_stdout")
	if ev["via"] != "ssh_stdout" || ev["action"] != "mask" || ev["masked_lines"] != 2 {
		t.Fatalf("%v", ev)
	}
}
