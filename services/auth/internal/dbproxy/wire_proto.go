package dbproxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

func randReader() io.Reader { return rand.Reader }

type pgMsg struct {
	tag  byte
	body []byte
}

func writePGMsg(w io.Writer, tag byte, body []byte) error {
	buf := make([]byte, 5+len(body))
	buf[0] = tag
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(body)+4))
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}

func readPGMsg(r io.Reader) (pgMsg, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return pgMsg{}, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
	if n < 0 || n > 16*1024*1024 {
		return pgMsg{}, fmt.Errorf("bad pg msg length")
	}
	body := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return pgMsg{}, err
		}
	}
	return pgMsg{tag: hdr[0], body: body}, nil
}

func parsePGStartup(rest []byte) map[string]string {
	out := map[string]string{}
	parts := strings.Split(string(rest), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		out[parts[i]] = parts[i+1]
	}
	return out
}

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMySQLPacket(r io.Reader) ([]byte, byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq := hdr[3]
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, 0, err
		}
	}
	return payload, seq, nil
}

func readNull(b []byte, i int) (string, int) {
	j := i
	for j < len(b) && b[j] != 0 {
		j++
	}
	s := string(b[i:j])
	if j < len(b) {
		j++
	}
	return s, j
}
