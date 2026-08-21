package filexfer

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseSCPStream extracts regular files from an SCP protocol byte stream
// (the direction that carries C/D/E/T headers and file bodies).
func ParseSCPStream(r io.Reader, onFile func(name, relPath string, body io.Reader, size int64) error) error {
	br := newByteReader(r)
	var stack []string
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch b {
		case 0, 1, 2:
			continue
		case 'T':
			if _, err := br.readLine(); err != nil {
				return err
			}
		case 'E':
			if _, err := br.readLine(); err != nil {
				return err
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case 'D':
			line, err := br.readLine()
			if err != nil {
				return err
			}
			_, _, name, err := parseCLine("D" + line)
			if err != nil {
				return err
			}
			stack = append(stack, name)
		case 'C':
			line, err := br.readLine()
			if err != nil {
				return err
			}
			_, size, name, err := parseCLine("C" + line)
			if err != nil {
				return err
			}
			rel := name
			if len(stack) > 0 {
				rel = strings.Join(append(append([]string{}, stack...), name), "/")
			}
			lr := io.LimitReader(br, size)
			if err := onFile(name, rel, lr, size); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, lr); err != nil {
				return err
			}
			ack, err := br.ReadByte()
			if err != nil && err != io.EOF {
				return err
			}
			if err == nil && ack != 0 {
				// leftover; ok
			}
		default:
			rest, err := br.readLine()
			if err != nil && err != io.EOF {
				return err
			}
			_ = rest
		}
	}
}

func parseCLine(line string) (mode string, size int64, name string, err error) {
	line = strings.TrimRight(line, "\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return "", 0, "", fmt.Errorf("bad scp header %q", line)
	}
	mode = parts[0]
	size, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 {
		return "", 0, "", fmt.Errorf("bad scp size")
	}
	name = strings.Trim(parts[2], "\r")
	if name == "" {
		name = "unnamed"
	}
	return mode, size, name, nil
}

type byteReader struct {
	r   io.Reader
	buf []byte
	off int
}

func newByteReader(r io.Reader) *byteReader {
	return &byteReader{r: r, buf: make([]byte, 0, 4096)}
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.off < len(b.buf) {
		n := copy(p, b.buf[b.off:])
		b.off += n
		if b.off == len(b.buf) {
			b.buf = b.buf[:0]
			b.off = 0
		}
		return n, nil
	}
	return b.r.Read(p)
}

func (b *byteReader) ReadByte() (byte, error) {
	var one [1]byte
	_, err := io.ReadFull(b, one[:])
	return one[0], err
}

func (b *byteReader) readLine() (string, error) {
	var buf bytes.Buffer
	for {
		c, err := b.ReadByte()
		if err != nil {
			if buf.Len() > 0 && err == io.EOF {
				return buf.String(), nil
			}
			return buf.String(), err
		}
		if c == '\n' {
			return buf.String(), nil
		}
		buf.WriteByte(c)
		if buf.Len() > 8192 {
			return "", fmt.Errorf("scp header too long")
		}
	}
}
