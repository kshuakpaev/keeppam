package castindex

import (
	"strings"
	"testing"
)

func TestInputLines(t *testing.T) {
	cast := `{"version":2,"width":80,"height":24}
[0.1, "o", "prompt$ "]
[0.2, "i", "l"]
[0.3, "i", "s"]
[0.4, "i", " -l"]
[0.5, "i", "\r"]
[0.6, "o", "file\n"]
[1.0, "i", "sudo rm -rf /tmp/x\n"]
[1.2, "i", "echo hi\n"]
`
	got, err := InputLines(strings.NewReader(cast))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	if got[0].Text != "ls -l" {
		t.Fatalf("first=%q", got[0].Text)
	}
	if got[1].Text != "sudo rm -rf /tmp/x" {
		t.Fatalf("second=%q", got[1].Text)
	}
	if got[2].Text != "echo hi" {
		t.Fatalf("third=%q", got[2].Text)
	}
}

func TestCleanLine(t *testing.T) {
	if CleanLine("  \x1b[31mrm\x1b[0m -rf /  ") != "rm -rf /" {
		t.Fatalf("%q", CleanLine("  \x1b[31mrm\x1b[0m -rf /  "))
	}
	if CleanLine("\x03") != "" {
		t.Fatal("control")
	}
}

func TestInputLinesEmpty(t *testing.T) {
	got, err := InputLines(strings.NewReader("{\"version\":2}\n[0,\"o\",\"hi\"]\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseCastOutput(t *testing.T) {
	cast := `{"version":2,"width":80,"height":24}
[0.1, "o", "prompt$ ls\r\n"]
[0.2, "i", "l"]
[0.3, "i", "s"]
[0.4, "i", "\r"]
[0.6, "o", "secret.txt\n"]
[0.7, "o", "secret.txt\r"]
[0.8, "o", "done\n"]
[0.9, "o", "$\n"]
`
	in, out, err := ParseCast(strings.NewReader(cast))
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 1 || in[0].Text != "ls" {
		t.Fatalf("in %+v", in)
	}
	if len(out) != 3 {
		t.Fatalf("out=%d %+v", len(out), out)
	}
	if out[0].Text != "prompt$ ls" || out[1].Text != "secret.txt" || out[2].Text != "done" {
		t.Fatalf("out %+v", out)
	}
}
