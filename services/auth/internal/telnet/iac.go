package telnet

// RFC 854 / 855 option negotiation helpers.

const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240

	optEcho  = 1
	optSGA   = 3
	optTType = 24
	optNAWS  = 31
)

// stripIAC removes negotiation sequences and returns application data.
// pending holds incomplete IAC at end of chunk (caller must retain across reads).
func stripIAC(in, pending []byte, onOpt func(cmd, opt byte), onSB func(opt byte, data []byte)) (out, rest []byte) {
	buf := append(append([]byte{}, pending...), in...)
	out = make([]byte, 0, len(buf))
	i := 0
	for i < len(buf) {
		if buf[i] != iac {
			out = append(out, buf[i])
			i++
			continue
		}
		if i+1 >= len(buf) {
			return out, buf[i:]
		}
		cmd := buf[i+1]
		switch cmd {
		case iac: // escaped 0xFF
			out = append(out, iac)
			i += 2
		case will, wont, do, dont:
			if i+2 >= len(buf) {
				return out, buf[i:]
			}
			if onOpt != nil {
				onOpt(cmd, buf[i+2])
			}
			i += 3
		case sb:
			j := i + 2
			for j+1 < len(buf) {
				if buf[j] == iac && buf[j+1] == se {
					if onSB != nil && i+2 < j {
						onSB(buf[i+2], buf[i+3:j])
					}
					i = j + 2
					break
				}
				j++
			}
			if j+1 >= len(buf) {
				return out, buf[i:]
			}
		default:
			i += 2
		}
	}
	return out, nil
}

func cmdOpt(cmd, opt byte) []byte {
	return []byte{iac, cmd, opt}
}

func nawsSub(cols, rows int) []byte {
	if cols < 1 {
		cols = 80
	}
	if rows < 1 {
		rows = 24
	}
	if cols > 65535 {
		cols = 65535
	}
	if rows > 65535 {
		rows = 65535
	}
	return []byte{
		iac, sb, optNAWS,
		byte(cols >> 8), byte(cols),
		byte(rows >> 8), byte(rows),
		iac, se,
	}
}

func ttypeIs(name string) []byte {
	if name == "" {
		name = "xterm-256color"
	}
	b := []byte{iac, sb, optTType, 0}
	b = append(b, name...)
	b = append(b, iac, se)
	return b
}
