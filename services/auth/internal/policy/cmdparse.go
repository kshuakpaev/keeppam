package policy

import (
	"path"
	"strings"
)

type ParsedCommand struct {
	Raw       string   `json:"raw"`
	Inner     string   `json:"inner"`
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	Wrappers  []string `json:"wrappers"`
	PrivShell bool     `json:"priv_shell"`
}

func splitShell(line string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	if out == nil {
		return []string{}
	}
	return out
}

func skipEnvAssign(fields []string) []string {
	for len(fields) > 0 {
		f := fields[0]
		eq := strings.IndexByte(f, '=')
		if eq <= 0 || strings.HasPrefix(f, "-") {
			break
		}
		fields = fields[1:]
	}
	return fields
}

func skipFlagArgs(fields []string, takesValue map[string]bool) []string {
	i := 0
	for i < len(fields) {
		f := fields[i]
		if f == "--" {
			return fields[i+1:]
		}
		if !strings.HasPrefix(f, "-") {
			return fields[i:]
		}
		if strings.Contains(f, "=") {
			i++
			continue
		}
		key := f
		if takesValue[key] {
			i += 2
			continue
		}
		i++
	}
	return fields[i:]
}

func skipSudoFlags(fields []string) []string {
	return skipFlagArgs(fields, map[string]bool{
		"-u": true, "--user": true, "-g": true, "--group": true,
		"-h": true, "--host": true, "-p": true, "--prompt": true,
		"-C": true, "--close-from": true, "-D": true, "--chdir": true,
		"-R": true, "--chroot": true, "-T": true, "--command-timeout": true,
		"-U": true, "--other-user": true,
	})
}

func parseSuRemainder(fields []string) []string {
	i := 0
	for i < len(fields) {
		f := fields[i]
		if f == "--" {
			if i+1 >= len(fields) {
				return nil
			}
			return fields[i+1:]
		}
		if f == "-c" || f == "--command" {
			if i+1 >= len(fields) {
				return nil
			}
			inner := splitShell(fields[i+1])
			if len(inner) == 0 {
				return nil
			}
			return inner
		}
		if strings.HasPrefix(f, "--command=") {
			inner := splitShell(strings.TrimPrefix(f, "--command="))
			if len(inner) == 0 {
				return nil
			}
			return inner
		}
		if f == "-s" || f == "--shell" {
			i += 2
			continue
		}
		if strings.HasPrefix(f, "-") {
			i++
			continue
		}
		i++ // username
	}
	return nil
}

func parseShellCRemainder(fields []string) []string {
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "-c", f == "--command":
			if i+1 >= len(fields) {
				return nil
			}
			return splitShell(fields[i+1])
		case strings.HasPrefix(f, "--command="):
			return splitShell(strings.TrimPrefix(f, "--command="))
		case strings.HasPrefix(f, "-") && strings.Contains(f, "c"):
			if strings.HasPrefix(f, "-c") && len(f) > 2 {
				return splitShell(f[2:])
			}
			if i+1 >= len(fields) {
				return nil
			}
			return splitShell(fields[i+1])
		}
	}
	return nil
}

// ParseCommand unwraps sudo/su/doas/env/nohup and returns the inner binary.
func ParseCommand(line string) ParsedCommand {
	raw := strings.TrimSpace(line)
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	p := ParsedCommand{Raw: raw, Args: []string{}, Wrappers: []string{}}
	fields := skipEnvAssign(splitShell(raw))
	for hops := 0; hops < 6 && len(fields) > 0; hops++ {
		base := strings.ToLower(path.Base(fields[0]))
		switch base {
		case "sudo", "doas", "pkexec":
			p.Wrappers = append(p.Wrappers, base)
			fields = skipSudoFlags(fields[1:])
			if len(fields) == 0 {
				p.PrivShell = true
				p.Binary = base
				p.Inner = base
				return p
			}
			continue
		case "su":
			p.Wrappers = append(p.Wrappers, "su")
			inner := parseSuRemainder(fields[1:])
			if inner == nil {
				p.PrivShell = true
				p.Binary = "su"
				p.Inner = "su"
				return p
			}
			fields = inner
			continue
		case "nohup", "nice", "time", "stdbuf", "env":
			p.Wrappers = append(p.Wrappers, base)
			fields = fields[1:]
			if base == "nice" || base == "stdbuf" || base == "env" {
				fields = skipFlagArgs(fields, map[string]bool{
					"-n": true, "-o": true, "-e": true, "-u": true, "-i": true,
				})
			}
			fields = skipEnvAssign(fields)
			continue
		case "bash", "sh", "dash", "zsh", "ksh":
			p.Wrappers = append(p.Wrappers, base)
			if inner := parseShellCRemainder(fields[1:]); inner != nil {
				fields = inner
				continue
			}
		}
		break
	}
	if len(fields) == 0 {
		return p
	}
	p.Binary = strings.ToLower(path.Base(fields[0]))
	if len(fields) > 1 {
		p.Args = fields[1:]
	}
	p.Inner = strings.Join(fields, " ")
	return p
}
