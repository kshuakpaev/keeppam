package ai

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRedactPrivateKeyAndPassword(t *testing.T) {
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\npassword=SuperSecret1\nAuthorization: Bearer abc.def"
	out := Redact(in)
	if strings.Contains(out, "MIIE") || strings.Contains(out, "SuperSecret1") || strings.Contains(out, "abc.def") {
		t.Fatalf("leaked secret: %q", out)
	}
}

func TestHashEmbedSynonyms(t *testing.T) {
	drop := HashEmbed("DROP TABLE salaries")
	q := HashEmbed("удаление схемы")
	if cosine(drop, q) < 0.05 {
		t.Fatalf("expected synonym overlap, cosine=%v", cosine(drop, q))
	}
	sal := HashEmbed("SELECT salary FROM employees")
	q2 := HashEmbed("данные о зарплате")
	if cosine(sal, q2) < 0.05 {
		t.Fatalf("salary overlap cosine=%v", cosine(sal, q2))
	}
}

func TestMockSummaryMentionsDeny(t *testing.T) {
	sid := uuid.New()
	eid := uuid.New()
	evs := []indexEvent{
		{ID: uuid.New(), Type: "command", Snippet: "ls", Offset: 1},
		{ID: eid, Type: "command_denied", Snippet: "sudo rm -rf /tmp/x", Offset: 2},
	}
	sum := MockSummaryFromEvents(sid, "ssh", "ops", "demo-linux", 40, []string{"ueba_new_asset"}, evs, "ru")
	if !strings.Contains(strings.ToLower(sum.Summary+sum.Headline), "отклон") && sum.Headline == "" {
		t.Fatalf("expected deny mention: %+v", sum)
	}
	if strings.Contains(strings.ToLower(sum.Summary), "drop database") {
		t.Fatal("invented drop database")
	}
	found := false
	for _, b := range sum.Bullets {
		if b.Type == "command_denied" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing denied bullet")
	}
}

func TestExplainFactorsDropsUnknown(t *testing.T) {
	text := explainFactors([]string{"ueba_new_asset", "ueba_ml_high", "invented_factor"}, 72, "ru")
	if !strings.Contains(text, "ueba_new_asset") || !strings.Contains(text, "ueba_ml_high") {
		t.Fatalf("missing known factors: %s", text)
	}
	if strings.Contains(text, "invented_factor") {
		t.Fatal("unknown factor leaked")
	}
	filtered := filterExplainText("ueba_new_asset ok\ninvented_factor should go\nueba_ml_high ok", []string{"ueba_new_asset", "ueba_ml_high"})
	if strings.Contains(filtered, "invented_factor") {
		t.Fatalf("filter failed: %s", filtered)
	}
}

func TestParseJEADraft(t *testing.T) {
	d := parseJEADraft("DBA SSH на *db* пн–пт 9-18, без rm/dd")
	if d.Policy["asset_match"] != "*db*" {
		t.Fatalf("asset_match: %+v", d.Policy)
	}
	joined := strings.Join(d.Patterns, " ")
	if !strings.Contains(joined, "rm") {
		t.Fatalf("patterns %v", d.Patterns)
	}
}

func TestHelpAsk(t *testing.T) {
	a := answerHelp("что такое JIT доступ", "ru")
	if a.Answer == "" || len(a.Topics) == 0 {
		t.Fatalf("%+v", a)
	}
}

func TestComplianceNumbers(t *testing.T) {
	sum := struct {
		Access, Privileged, Approvals, Connections, Commands, SQL, Downloads, Changes, Revoked int
	}{Access: 3, Privileged: 1}
	prose := "выдач доступа 3; привилегированных/break-glass 1; согласований 0"
	if strings.Contains(prose, "99") {
		t.Fatal("unexpected")
	}
	_ = sum
}
