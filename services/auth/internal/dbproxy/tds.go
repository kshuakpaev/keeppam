package dbproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

const (
	tdsSQLBatch  byte = 0x01
	tdsRPC       byte = 0x03
	tdsTabular   byte = 0x04
	tdsAttention byte = 0x06
	tdsBulk      byte = 0x07
	tdsTM        byte = 0x0E
	tdsLogin7    byte = 0x10
	tdsPrelogin  byte = 0x12

	tdsEOM           byte = 0x01
	tdsEncryptNotSup byte = 0x02

	tdsPktSize = 4096
)

func readTDSMessage(r io.Reader) (typ byte, payload []byte, err error) {
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return 0, nil, err
		}
		pktType := hdr[0]
		status := hdr[1]
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < 8 || n > 16*1024*1024 {
			return 0, nil, fmt.Errorf("bad TDS length %d", n)
		}
		body := make([]byte, n-8)
		if len(body) > 0 {
			if _, err := io.ReadFull(r, body); err != nil {
				return 0, nil, err
			}
		}
		if typ == 0 {
			typ = pktType
		} else if pktType != typ {
			return 0, nil, fmt.Errorf("TDS type changed mid-message")
		}
		payload = append(payload, body...)
		if status&tdsEOM != 0 {
			return typ, payload, nil
		}
	}
}

func writeTDSMessage(w io.Writer, typ byte, payload []byte) error {
	max := tdsPktSize - 8
	if max < 1 {
		max = 4088
	}
	off := 0
	pktID := byte(1)
	if len(payload) == 0 {
		return writeTDSPacket(w, typ, tdsEOM, pktID, nil)
	}
	for off < len(payload) {
		end := off + max
		status := byte(0)
		if end >= len(payload) {
			end = len(payload)
			status = tdsEOM
		}
		if err := writeTDSPacket(w, typ, status, pktID, payload[off:end]); err != nil {
			return err
		}
		off = end
		pktID++
	}
	return nil
}

func writeTDSPacket(w io.Writer, typ, status, pktID byte, body []byte) error {
	n := 8 + len(body)
	hdr := make([]byte, 8)
	hdr[0] = typ
	hdr[1] = status
	binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
	hdr[6] = pktID
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

func writePreloginResponse(w io.Writer) error {
	// VERSION @11 (6 bytes), ENCRYPTION @17 (1 byte = NOT_SUP).
	b := []byte{
		0x00, 0x00, 0x0B, 0x00, 0x06,
		0x01, 0x00, 0x11, 0x00, 0x01,
		0xFF,
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
		tdsEncryptNotSup,
	}
	return writeTDSMessage(w, tdsPrelogin, b)
}

func parseLogin7(payload []byte) (user, pass, database string, err error) {
	if len(payload) < 94 {
		return "", "", "", fmt.Errorf("short LOGIN7")
	}
	user = readLogin7Str(payload, 40, 42, false)
	pass = readLogin7Str(payload, 44, 46, true)
	database = readLogin7Str(payload, 68, 70, false)
	if i := strings.LastIndexAny(user, "\\/"); i >= 0 {
		user = user[i+1:]
	}
	return strings.TrimSpace(user), pass, strings.TrimSpace(database), nil
}

func readLogin7Str(payload []byte, ibOff, cchOff int, password bool) string {
	if cchOff+2 > len(payload) {
		return ""
	}
	ib := int(binary.LittleEndian.Uint16(payload[ibOff : ibOff+2]))
	cch := int(binary.LittleEndian.Uint16(payload[cchOff : cchOff+2]))
	if cch == 0 || ib < 0 || ib+2*cch > len(payload) {
		return ""
	}
	raw := append([]byte(nil), payload[ib:ib+2*cch]...)
	if password {
		raw = tdsDeobfuscateBytes(raw)
	}
	return decodeUCS2(raw)
}

func tdsObfuscate(s string) []byte {
	b := encodeUCS2(s)
	for i := range b {
		x := ((b[i] & 0x0F) << 4) | (b[i] >> 4)
		b[i] = x ^ 0xA5
	}
	return b
}

func tdsDeobfuscateBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		x := b[i] ^ 0xA5
		out[i] = ((x & 0x0F) << 4) | (x >> 4)
	}
	return out
}

func sqlBatchText(payload []byte) string {
	if len(payload) >= 8 {
		total := int(binary.LittleEndian.Uint32(payload[0:4]))
		hdrLen := int(binary.LittleEndian.Uint32(payload[4:8]))
		if total >= 8 && total <= len(payload) && hdrLen >= 4 && hdrLen <= total {
			payload = payload[total:]
		}
	}
	return strings.TrimSpace(decodeUCS2(payload))
}

func encodeUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

func decodeUCS2(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func appendBVarChar(dst []byte, s string) []byte {
	u := encodeUCS2(s)
	n := len(u) / 2
	if n > 255 {
		n = 255
		u = u[:510]
	}
	dst = append(dst, byte(n))
	return append(dst, u...)
}

func appendUSVarChar(dst []byte, s string) []byte {
	u := encodeUCS2(s)
	n := len(u) / 2
	if n > 65535 {
		n = 65535
		u = u[:n*2]
	}
	dst = binary.LittleEndian.AppendUint16(dst, uint16(n))
	return append(dst, u...)
}

func tdsLoginAck(database string) []byte {
	if database == "" {
		database = "master"
	}
	var b []byte
	ackInner := []byte{0x01} // SQL
	ackInner = binary.LittleEndian.AppendUint32(ackInner, 0x74000004)
	ackInner = appendBVarChar(ackInner, "KeepPAM")
	ackInner = binary.LittleEndian.AppendUint32(ackInner, 0x00000001)
	b = append(b, 0xAD)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(ackInner)))
	b = append(b, ackInner...)

	env := []byte{0x01} // database
	env = appendBVarChar(env, database)
	env = appendBVarChar(env, "")
	b = append(b, 0xE3)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(env)))
	b = append(b, env...)

	b = append(b, tdsDONE(0x00, 0)...)
	return b
}

func tdsDONE(status uint16, rowCount uint64) []byte {
	b := []byte{0xFD}
	b = binary.LittleEndian.AppendUint16(b, status)
	b = binary.LittleEndian.AppendUint16(b, 0) // curcmd
	b = binary.LittleEndian.AppendUint64(b, rowCount)
	return b
}

func tdsError(msg string) []byte {
	if msg == "" {
		msg = "error"
	}
	inner := make([]byte, 0, 64+len(msg)*2)
	inner = binary.LittleEndian.AppendUint32(inner, 50000)
	inner = append(inner, 1, 14) // state, class
	inner = appendUSVarChar(inner, msg)
	inner = appendBVarChar(inner, "KeepPAM")
	inner = appendBVarChar(inner, "")
	inner = binary.LittleEndian.AppendUint32(inner, 1)
	b := []byte{0xAA}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(inner)))
	b = append(b, inner...)
	b = append(b, tdsDONE(0x02, 0)...) // DONE_ERROR
	return b
}

var tdsCollation = []byte{0x09, 0x04, 0xD0, 0x00, 0x34}

func tdsResultSet(cols []string, rows [][]string) []byte {
	var b []byte
	if len(cols) == 0 {
		return tdsDONE(0x10, uint64(len(rows)))
	}
	b = append(b, 0x81) // COLMETADATA
	b = binary.LittleEndian.AppendUint16(b, uint16(len(cols)))
	for _, name := range cols {
		b = binary.LittleEndian.AppendUint32(b, 0)      // usertype
		b = binary.LittleEndian.AppendUint16(b, 0x0020) // nullable
		b = append(b, 0xE7)                             // NVARCHAR
		b = binary.LittleEndian.AppendUint16(b, 8000)
		b = append(b, tdsCollation...)
		b = appendBVarChar(b, name)
	}
	for _, row := range rows {
		b = append(b, 0xD1)
		for i := range cols {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			if cell == "NULL" && (i >= len(row) || row[i] == "NULL") {
				// still send as text; NULL marker only if empty and flagged — keep simple
			}
			u := encodeUCS2(cell)
			if len(u) > 8000 {
				u = u[:8000]
			}
			b = binary.LittleEndian.AppendUint16(b, uint16(len(u)))
			b = append(b, u...)
		}
	}
	b = append(b, tdsDONE(0x10, uint64(len(rows)))...)
	return b
}

func buildLogin7ForTest(user, pass, database string) []byte {
	const hdr = 94
	userB := encodeUCS2(user)
	passB := tdsObfuscate(pass)
	dbB := encodeUCS2(database)
	off := hdr
	put := func(s []byte) int {
		ib := off
		off += len(s)
		return ib
	}
	uib := put(userB)
	pib := put(passB)
	dib := put(dbB)
	buf := make([]byte, off)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(off))
	binary.LittleEndian.PutUint32(buf[4:8], 0x74000004)
	binary.LittleEndian.PutUint32(buf[8:12], 4096)
	binary.LittleEndian.PutUint16(buf[40:42], uint16(uib))
	binary.LittleEndian.PutUint16(buf[42:44], uint16(len(userB)/2))
	binary.LittleEndian.PutUint16(buf[44:46], uint16(pib))
	binary.LittleEndian.PutUint16(buf[46:48], uint16(len(passB)/2))
	binary.LittleEndian.PutUint16(buf[68:70], uint16(dib))
	binary.LittleEndian.PutUint16(buf[70:72], uint16(len(dbB)/2))
	copy(buf[uib:], userB)
	copy(buf[pib:], passB)
	copy(buf[dib:], dbB)
	return buf
}
