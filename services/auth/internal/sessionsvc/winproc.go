package sessionsvc

import (
	"regexp"
	"strings"
	"unicode"
)

// WinProcessHit is a best-effort Windows process observation (no agent on target).
type WinProcessHit struct {
	Name       string
	Title      string
	Source     string
	Confidence string
	Offset     float64
}

var (
	reExeToken   = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9_.-]{0,62}\.exe)\b`)
	reTaskMgrRow = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9_.-]{0,62}\.exe)\s+\d{2,6}\b`)
	reKeystrokeExe = regexp.MustCompile(`(?i)^(?:[a-z]:\\)?(?:[\w.-]+\\)*[\w.-]+\.exe$`)
)

var titleToExe = map[string]string{
	"notepad":                   "notepad.exe",
	"блокнот":                   "notepad.exe",
	"command prompt":            "cmd.exe",
	"командная строка":           "cmd.exe",
	"windows powershell":        "powershell.exe",
	"powershell":                "powershell.exe",
	"task manager":              "Taskmgr.exe",
	"диспетчер задач":           "Taskmgr.exe",
	"file explorer":             "explorer.exe",
	"проводник":                 "explorer.exe",
	"registry editor":           "regedit.exe",
	"remote desktop connection": "mstsc.exe",
	"calculator":                "calc.exe",
	"калькулятор":               "calc.exe",
	"paint":                     "mspaint.exe",
	"word":                      "winword.exe",
	"excel":                     "excel.exe",
	"outlook":                   "outlook.exe",
}

var keystrokeToExe = map[string]string{
	"notepad":    "notepad.exe",
	"calc":       "calc.exe",
	"calculator": "calc.exe",
	"mspaint":    "mspaint.exe",
	"paint":      "mspaint.exe",
	"cmd":        "cmd.exe",
	"powershell": "powershell.exe",
	"taskmgr":    "Taskmgr.exe",
	"explorer":   "explorer.exe",
	"regedit":    "regedit.exe",
	"mstsc":      "mstsc.exe",
}

// ExtractWinProcesses derives process names from OCR window titles, screen lines, and keystrokes.
func ExtractWinProcesses(screen, keystrokes []TranscriptLine) []WinProcessHit {
	seen := map[string]struct{}{}
	var out []WinProcessHit
	add := func(hit WinProcessHit) {
		if hit.Name == "" {
			return
		}
		key := strings.ToLower(hit.Name) + "|" + hit.Source
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, hit)
	}

	titles := WindowTitlesFromScreen(screen)
	for _, ln := range titles {
		title := strings.TrimSpace(ln.Command)
		if exe := exeFromTitle(title); exe != "" {
			add(WinProcessHit{
				Name: normalizeExe(exe), Title: title, Source: "ocr_title",
				Confidence: "medium", Offset: ln.Offset,
			})
		}
	}
	for _, ln := range screen {
		text := strings.TrimSpace(ln.Command)
		if text == "" {
			continue
		}
		for _, line := range splitLines(text) {
			if m := reTaskMgrRow.FindStringSubmatch(line); len(m) == 2 {
				add(WinProcessHit{
					Name: normalizeExe(m[1]), Source: "taskmgr",
					Confidence: "high", Offset: ln.Offset,
				})
				continue
			}
			for _, m := range reExeToken.FindAllStringSubmatch(line, -1) {
				add(WinProcessHit{
					Name: normalizeExe(m[1]), Source: "ocr_screen",
					Confidence: "high", Offset: ln.Offset,
				})
			}
		}
	}
	for _, ln := range keystrokes {
		line := strings.TrimSpace(ln.Command)
		if line == "" {
			continue
		}
		if reKeystrokeExe.MatchString(line) {
			add(WinProcessHit{
				Name: normalizeExe(line), Source: "keystroke",
				Confidence: "high", Offset: ln.Offset,
			})
			continue
		}
		low := strings.ToLower(strings.Trim(line, `"'`))
		if exe, ok := keystrokeToExe[low]; ok {
			add(WinProcessHit{
				Name: normalizeExe(exe), Source: "keystroke",
				Confidence: "medium", Offset: ln.Offset,
			})
		}
	}
	if out == nil {
		return []WinProcessHit{}
	}
	return out
}

func exeFromTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return ""
	}
	if m := reExeToken.FindStringSubmatch(title); len(m) == 2 {
		return m[1]
	}
	low := strings.ToLower(title)
	if i := strings.Index(low, " - "); i > 0 {
		tail := strings.TrimSpace(low[i+3:])
		if exe, ok := titleToExe[tail]; ok {
			return exe
		}
		low = strings.TrimSpace(low[:i])
	}
	if exe, ok := titleToExe[low]; ok {
		return exe
	}
	for prefix, exe := range titleToExe {
		if strings.HasPrefix(low, prefix+" ") || strings.HasPrefix(low, prefix+"-") {
			return exe
		}
	}
	return ""
}

func normalizeExe(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Trim(name, `"'`)
	if name == "" {
		return ""
	}
	base := name
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		base = name[i+1:]
	}
	low := strings.ToLower(base)
	if !strings.HasSuffix(low, ".exe") {
		low += ".exe"
		base = low
	}
	stem := low[:len(low)-4]
	runes := []rune(stem)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
		for i := 1; i < len(runes); i++ {
			runes[i] = unicode.ToLower(runes[i])
		}
	}
	return string(runes) + ".exe"
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	parts := strings.Split(s, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
