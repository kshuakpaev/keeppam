package guacindex

import (
	"strconv"
	"strings"
	"testing"
)

func enc(parts ...string) string {
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte('.')
		b.WriteString(p)
	}
	b.WriteByte(';')
	return b.String()
}

func TestParseKeys(t *testing.T) {
	dump := enc("nop") +
		enc("sync", "1500") +
		enc("key", "108", "1") + // l
		enc("key", "108", "0") +
		enc("key", "115", "1") + // s
		enc("key", "65293", "1") + // Return
		enc("key", "97", "1") + // a
		enc("key", "65288", "1") + // BackSpace
		enc("key", "98", "1") + // b
		enc("key", "65293", "1")
	got, err := ParseKeys(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	if got[0].Text != "ls" || got[0].Offset != 1.5 {
		t.Fatalf("first %+v", got[0])
	}
	if got[1].Text != "b" {
		t.Fatalf("second %+v", got[1])
	}
}

func TestParseKeysUnicode(t *testing.T) {
	ks := strconv.Itoa(0x01000000 + int('а'))
	dump := enc("key", ks, "1") + enc("key", "65293", "1")
	got, err := ParseKeys(strings.NewReader(dump))
	if err != nil || len(got) != 1 || got[0].Text != "а" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestParseKeysEmpty(t *testing.T) {
	got, err := ParseKeys(strings.NewReader(enc("nop") + enc("mouse", "1", "10", "10")))
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseKeysTiming(t *testing.T) {
	dump := enc("sync", "0") +
		enc("key", "97", "1") +
		enc("sync", "100") +
		enc("key", "98", "1") +
		enc("sync", "200") +
		enc("key", "99", "1") +
		enc("sync", "300") +
		enc("key", "100", "1")
	_, tim, err := ParseKeysAndTiming(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if tim.NKeys != 4 || tim.Intervals != 3 {
		t.Fatalf("timing %+v", tim)
	}
	if tim.MedianMs != 100 {
		t.Fatalf("median=%v", tim.MedianMs)
	}
}

func TestParseMouseTiming(t *testing.T) {
	dump := enc("sync", "0") +
		enc("mouse", "0", "0", "0") +
		enc("sync", "10") +
		enc("mouse", "0", "100", "0") +
		enc("sync", "20") +
		enc("mouse", "0", "200", "0") +
		enc("sync", "30") +
		enc("mouse", "0", "300", "0")
	_, _, mouse, err := ParseKeysMouseAndTiming(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if mouse.NMoves != 4 || mouse.Samples < 2 || mouse.MedianVel < 5 {
		t.Fatalf("%+v", mouse)
	}
}


