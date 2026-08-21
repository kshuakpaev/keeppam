package termcharset

import (
	"testing"

	"golang.org/x/text/encoding/charmap"
)

func TestDecodeKOI8R(t *testing.T) {
	// "привет" in KOI8-R
	raw, err := charmap.KOI8R.NewEncoder().Bytes([]byte("привет"))
	if err != nil {
		t.Fatal(err)
	}
	got := Decode(raw, KOI8R)
	if got.Text != "привет" {
		t.Fatalf("got %q charset=%s", got.Text, got.Charset)
	}
	if got.Charset != KOI8R || got.RawB64 == "" {
		t.Fatalf("meta %+v", got)
	}
}

func TestDecodeCP1251(t *testing.T) {
	raw, err := charmap.Windows1251.NewEncoder().Bytes([]byte("секрет"))
	if err != nil {
		t.Fatal(err)
	}
	got := Decode(raw, CP1251)
	if got.Text != "секрет" {
		t.Fatalf("got %q", got.Text)
	}
}

func TestDecodeUTF8Passthrough(t *testing.T) {
	got := Decode([]byte("привет"), UTF8)
	if got.Text != "привет" || got.Charset != UTF8 {
		t.Fatalf("%+v", got)
	}
}

func TestAutoPrefersKOI8(t *testing.T) {
	raw, err := charmap.KOI8R.NewEncoder().Bytes([]byte("пароль"))
	if err != nil {
		t.Fatal(err)
	}
	got := Decode(raw, Auto)
	if got.Text != "пароль" {
		t.Fatalf("got %q via %s", got.Text, got.Charset)
	}
}

func TestNormalize(t *testing.T) {
	if Normalize("Windows-1251") != CP1251 || Normalize("koi8r") != KOI8R {
		t.Fatal(Normalize("Windows-1251"), Normalize("koi8r"))
	}
}
