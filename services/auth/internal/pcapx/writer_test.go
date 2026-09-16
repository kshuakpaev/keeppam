package pcapx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWriteStreamMagic(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("KeepPAM session recording")
	if err := WriteStream(&buf, payload); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) < 24+16 {
		t.Fatalf("too short: %d", len(b))
	}
	if magic := binary.LittleEndian.Uint32(b[0:4]); magic != magicMicro {
		t.Fatalf("magic=%x", magic)
	}
	if !bytes.Contains(b, payload) {
		t.Fatal("payload missing from pcap frames")
	}
}

func TestWriteStreamEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteStream(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 40 {
		t.Fatalf("len=%d", buf.Len())
	}
}
