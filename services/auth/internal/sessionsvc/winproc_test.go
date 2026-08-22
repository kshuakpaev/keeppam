package sessionsvc

import "testing"

func TestExtractWinProcesses(t *testing.T) {
	screen := []TranscriptLine{
		{Command: "Notepad\nFile Edit", Offset: 1},
		{Command: "Task Manager\nchrome.exe 1234 12", Offset: 5},
		{Command: "Background\npowershell.exe running", Offset: 8},
	}
	keys := []TranscriptLine{
		{Command: "notepad", Offset: 0.5},
		{Command: `C:\Windows\System32\cmd.exe`, Offset: 2},
	}
	got := ExtractWinProcesses(screen, keys)
	if len(got) < 4 {
		t.Fatalf("expected several hits, got %d: %+v", len(got), got)
	}
	names := map[string]bool{}
	for _, h := range got {
		names[h.Name] = true
	}
	for _, want := range []string{"Notepad.exe", "Chrome.exe", "Powershell.exe", "Cmd.exe"} {
		if !names[want] {
			t.Fatalf("missing %s in %+v", want, got)
		}
	}
}

func TestNormalizeExe(t *testing.T) {
	if got := normalizeExe("chrome"); got != "Chrome.exe" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeExe(`C:\Temp\FOO.EXE`); got != "Foo.exe" {
		t.Fatalf("got %q", got)
	}
}

func TestExeFromTitle(t *testing.T) {
	if got := exeFromTitle("Untitled - Notepad"); got != "notepad.exe" {
		t.Fatalf("got %q", got)
	}
	if got := exeFromTitle("CustomApp.exe - Window"); got != "CustomApp.exe" {
		t.Fatalf("got %q", got)
	}
}
