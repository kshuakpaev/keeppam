package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"
)

const testKey = "your-32-byte-encryption-key-change-me!!"

func signEx2Test(key string, p Ex2Payload) string {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte(p.HardwareFingerprint))
	var days [4]byte
	binary.LittleEndian.PutUint32(days[:], p.Days)
	h.Write(days[:])
	h.Write([]byte(p.IssuedBy))
	h.Write([]byte(ex2IssuedAtString(p.IssuedAt)))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func encryptEx2Test(key string, p Ex2Payload) ([]byte, error) {
	p.Signature = signEx2Test(key, p)
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(normalizeKey32(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, b, nil)
	out := append(nonce, ct...)
	return out, nil
}

func TestEx2Roundtrip(t *testing.T) {
	issued := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	max := 250
	p := Ex2Payload{
		HardwareFingerprint: "*",
		Days:                30,
		IssuedAt:            issued,
		IssuedBy:            "KeepPAM Lab",
		MaxAssets:           &max,
		Customer:            "Acme",
	}
	blob, err := encryptEx2Test(testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := ParseEx2Blob(testKey, blob, true)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Days != 30 || got.MaxAssets != 250 || got.Customer != "Acme" {
		t.Fatalf("%+v %+v", got, raw)
	}
	if got.Expires != "2026-02-14" {
		t.Fatalf("expires %q", got.Expires)
	}
}

func TestNormalizeEx2BlobBase64(t *testing.T) {
	issued := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	p := Ex2Payload{
		HardwareFingerprint: "*",
		Days:                7,
		IssuedAt:            issued,
		IssuedBy:            "x",
	}
	blob, err := encryptEx2Test(testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	b64 := []byte(base64.StdEncoding.EncodeToString(blob))
	got := NormalizeEx2Blob(b64)
	if len(got) != len(blob) {
		t.Fatalf("len %d want %d", len(got), len(blob))
	}
	if _, _, err := ParseEx2Blob(testKey, got, true); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeEx2BlobJSONWrapper(t *testing.T) {
	issued := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	p := Ex2Payload{
		HardwareFingerprint: "*",
		Days:                7,
		IssuedAt:            issued,
		IssuedBy:            "x",
	}
	blob, err := encryptEx2Test(testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := json.Marshal(map[string]string{
		"license_file": base64.StdEncoding.EncodeToString(blob),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := NormalizeEx2Blob(wrap)
	if len(got) != len(blob) {
		t.Fatalf("len %d want %d", len(got), len(blob))
	}
}

func TestEx2ChronoIssuedAtFormat(t *testing.T) {
	issued := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	if got := ex2IssuedAtString(issued); got != "2026-01-15T12:00:00+00:00" {
		t.Fatalf("got %q", got)
	}
	withMs := time.Date(2026, 8, 23, 9, 31, 0, 123000000, time.UTC)
	if got := ex2IssuedAtString(withMs); got != "2026-08-23T09:31:00.123+00:00" {
		t.Fatalf("ms got %q", got)
	}
	withUs := time.Date(2026, 8, 23, 9, 31, 0, 123456000, time.UTC)
	if got := ex2IssuedAtString(withUs); got != "2026-08-23T09:31:00.123456+00:00" {
		t.Fatalf("us got %q", got)
	}
}

func TestEx2RoundtripWithMillis(t *testing.T) {
	issued := time.Date(2026, 8, 23, 9, 31, 0, 123000000, time.UTC)
	max := 250
	p := Ex2Payload{
		HardwareFingerprint: "*",
		Days:                30,
		IssuedAt:            issued,
		IssuedBy:            "KeepPAM Lab",
		MaxAssets:           &max,
		Customer:            "Acme",
	}
	blob, err := encryptEx2Test(testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseEx2Blob(testKey, blob, true); err != nil {
		t.Fatal(err)
	}
}

func TestEx2BadSignature(t *testing.T) {
	issued := time.Now().UTC()
	p := Ex2Payload{
		HardwareFingerprint: "*",
		Days:                7,
		IssuedAt:            issued,
		IssuedBy:            "x",
		Signature:           "bad",
	}
	b, _ := json.Marshal(p)
	block, _ := aes.NewCipher(normalizeKey32(testKey))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, nonce)
	blob := append(nonce, gcm.Seal(nil, nonce, b, nil)...)
	if _, _, err := ParseEx2Blob(testKey, blob, true); err == nil {
		t.Fatal("expected signature error")
	}
}
