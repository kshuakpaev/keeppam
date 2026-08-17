package compliance

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNormalizeFramework(t *testing.T) {
	if NormalizeFramework("ISO-27001") != "iso27001" {
		t.Fatal(NormalizeFramework("ISO-27001"))
	}
	if NormalizeFramework("pci-dss") != "pci" {
		t.Fatal()
	}
	if NormalizeFramework("") != "all" {
		t.Fatal()
	}
}

func TestFrameworkControls(t *testing.T) {
	iso := FrameworkControls("iso27001")
	if len(iso) != 3 || iso[0].ID != "A.9" {
		t.Fatalf("%+v", iso)
	}
	all := FrameworkControls("all")
	if len(all) != 11 {
		t.Fatalf("want 11 got %d", len(all))
	}
	if !strings.HasPrefix(all[0].ID, "iso27001:") {
		t.Fatal(all[0].ID)
	}
}

func TestParseReportWindowDefault(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	from, to, err := ParseReportWindow("", "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if !to.Equal(now) {
		t.Fatalf("to %s", to)
	}
	if to.Sub(from) != 30*24*time.Hour {
		t.Fatalf("span %s", to.Sub(from))
	}
}

func TestParseReportWindowClamp(t *testing.T) {
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	from, to, err := ParseReportWindow("2025-01-01T00:00:00Z", "2026-08-16T00:00:00Z", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if to.Sub(from) != 90*24*time.Hour {
		t.Fatalf("span %s", to.Sub(from))
	}
}

func TestParseReportWindowDateOnly(t *testing.T) {
	from, to, err := ParseReportWindow("2026-08-01", "2026-08-01", 0, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if from.Day() != 1 || from.Hour() != 0 {
		t.Fatalf("from %s", from)
	}
	if to.Day() != 1 || to.Hour() != 23 {
		t.Fatalf("to %s", to)
	}
}

func TestEvidenceCategory(t *testing.T) {
	cases := []struct {
		src, kind, want string
	}{
		{"audit", "asset.acl.granted", CatAccess},
		{"audit", "asset.acl.updated", CatChanges},
		{"audit", "asset.acl.revoked", CatRevoked},
		{"audit", "user.disabled", CatRevoked},
		{"audit", "access.breakglass.opened", CatPrivileged},
		{"audit", "session.admin_bypass", CatPrivileged},
		{"audit", "access.request.approved", CatApprovals},
		{"audit", "asset.account.checkout.denied", CatApprovals},
		{"audit", "session.created", CatConnections},
		{"audit", "session.denied", CatConnections},
		{"audit", "k8s.access.granted", CatConnections},
		{"audit", "asset.account.secret_revealed", CatDownloads},
		{"audit", "session.export_mp4", CatDownloads},
		{"audit", "session.dlp.denied", CatDownloads},
		{"audit", "session.dlp.masked", CatDownloads},
		{"audit", "session.egress.denied", CatDownloads},
		{"audit", "session.egress.opened", CatDownloads},
		{"audit", "user.created", CatChanges},
		{"audit", "group.membership", CatChanges},
		{"audit", "role.assigned", CatChanges},
		{"audit", "access.policy.updated", CatChanges},
		{"audit", "asset.created", CatChanges},
		{"audit", "jea.pack.created", CatChanges},
		{"audit", "access.risk.evaluated", ""},
		{"audit", "user.login.success", ""},
		{"audit", "session.command.denied", CatCommands},
		{"audit", "session.command.approval_required", CatCommands},
		{"audit", "session.command.approved", CatApprovals},
		{"session", "sql", CatSQL},
		{"session", "sql_denied", CatSQL},
		{"session", "command_denied", CatCommands},
		{"session", "command_approval", CatCommands},
		{"session", "command_approved", CatApprovals},
		{"session", "k8s", CatCommands},
		{"session", "http_denied", CatCommands},
		{"session", "app_denied", CatCommands},
		{"session", "app_approval", CatCommands},
		{"audit", "session.app.denied", CatCommands},
		{"audit", "session.app.approval_required", CatCommands},
		{"audit", "session.app.approved", CatApprovals},
		{"session", "app_approved", CatApprovals},
		{"audit", "session.op.approved", CatApprovals},
		{"audit", "session.op.denied", CatApprovals},
		{"session", "dlp", CatDownloads},
		{"session", "egress", CatDownloads},
		{"session", "egress_denied", CatDownloads},
		{"session", "started", CatConnections},
		{"session", "risk", CatCommands},
	}
	for _, c := range cases {
		got := EvidenceCategory(c.src, c.kind)
		if got != c.want {
			t.Errorf("%s %s: got %q want %q", c.src, c.kind, got, c.want)
		}
	}
	if !IsPrivileged("audit", "access.request.approved") {
		t.Fatal("approved is privileged")
	}
	if IsPrivileged("session", "sql") {
		t.Fatal("sql not privileged")
	}
}

func TestWriteReportPDF(t *testing.T) {
	var buf bytes.Buffer
	rep := Report{
		GeneratedAt: time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC),
		From:        time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC),
		To:          time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC),
		Framework:   "iso27001",
		Controls:    FrameworkControls("iso27001"),
		Summary:     ReportSummary{Access: 3, SQL: 1},
		Snapshot:    ReportSnapshot{ACLLive: 4, SessionsActive: 1},
		Evidence: []EvidenceRow{{
			TS:       time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC),
			Category: CatAccess, Source: "audit", Actor: "admin",
			Action: "asset.acl.granted", Detail: "granted (acl)",
		}, {
			TS:       time.Date(2026, 8, 16, 11, 0, 0, 0, time.UTC),
			Category: CatSQL, Actor: "оператор",
			Action: "sql", Detail: "SELECT 1",
		}},
		EvidenceTotal: 2,
		Notes:         reportNotes(),
	}
	if err := WriteReportPDF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "%PDF-1.4") {
		t.Fatalf("magic %q", got[:min(20, len(got))])
	}
	if !strings.Contains(got, "%%EOF") || !strings.Contains(got, "startxref") {
		t.Fatal("trailer")
	}
	if !strings.Contains(got, "KeepPAM Compliance Report") {
		t.Fatal("title")
	}
	if !strings.Contains(got, "iso27001") || !strings.Contains(got, "asset.acl.granted") {
		t.Fatal("body")
	}
	if !strings.Contains(got, pdfLatin("оператор")) {
		t.Fatalf("cyrillic actor missing, want %q", pdfLatin("оператор"))
	}
	if strings.Contains(got, "оператор") {
		t.Fatal("raw cyrillic in PDF")
	}
	if !strings.Contains(got, "/BaseFont /Helvetica") {
		t.Fatal("font")
	}
}

func TestWriteReportPDFPages(t *testing.T) {
	ev := make([]EvidenceRow, 80)
	for i := range ev {
		ev[i] = EvidenceRow{
			TS:       time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC),
			Category: CatCommands, Actor: "admin", Action: "session.command.denied",
			Detail: "rm -rf /",
		}
	}
	var buf bytes.Buffer
	if err := WriteReportPDF(&buf, Report{Framework: "all", Evidence: ev, EvidenceTotal: 80, Controls: FrameworkControls("all")}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "KeepPAM  1/1 confidential") {
		t.Fatal("expected multi-page")
	}
	if !strings.Contains(got, "KeepPAM  1/") {
		t.Fatal("footer")
	}
	if strings.Count(got, " 0 obj") < 7 {
		t.Fatalf("too few objects: %d", strings.Count(got, " 0 obj"))
	}
}

func TestPdfLatin(t *testing.T) {
	if pdfLatin("оператор") != "operator" {
		t.Fatal(pdfLatin("оператор"))
	}
	if pdfLatin("a(b)") != "a(b)" {
		t.Fatal(pdfLatin("a(b)"))
	}
}

func TestWriteReportPDFSignedNote(t *testing.T) {
	var buf bytes.Buffer
	if err := writeReportPDF(&buf, Report{Framework: "all", GeneratedAt: time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)}, "PAdES-B-B (CAdES detached, no TSA/LTV)"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "PAdES-B-B") {
		t.Fatal("signed note")
	}
}

func TestWriteReportCSV(t *testing.T) {
	var buf bytes.Buffer
	rep := Report{Evidence: []EvidenceRow{{
		TS:       time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC),
		Category: CatAccess, Source: "audit", Actor: "admin",
		Action: "asset.acl.granted", ResourceType: "asset", ResourceID: "abc",
		Detail: "granted", IP: "10.0.0.1",
	}}}
	if err := WriteReportCSV(&buf, rep); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "category") || !strings.Contains(got, "asset.acl.granted") {
		t.Fatal(got)
	}
}
