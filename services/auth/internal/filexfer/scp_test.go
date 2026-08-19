package filexfer

import (
	"bytes"
	"io"
	"testing"
)

func TestParseSCPStream(t *testing.T) {
	body := []byte("hello keeppam")
	var buf bytes.Buffer
	buf.WriteString("C0644 13 hello.txt\n")
	buf.Write(body)
	buf.WriteByte(0)
	var gotName string
	var gotBody []byte
	err := ParseSCPStream(&buf, func(name, rel string, r io.Reader, size int64) error {
		gotName = name
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		gotBody = b
		if int64(len(gotBody)) != size {
			t.Fatalf("size %d != %d", len(gotBody), size)
		}
		_ = rel
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotName != "hello.txt" || string(gotBody) != "hello keeppam" {
		t.Fatalf("name=%q body=%q", gotName, gotBody)
	}
}
