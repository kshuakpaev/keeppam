package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/keeppam/auth/internal/license"
)

const key = "your-32-byte-encryption-key-change-me!!"

type payload struct {
	HardwareFingerprint string    `json:"hardware_fingerprint"`
	Days                uint32    `json:"days"`
	IssuedAt            time.Time `json:"issued_at"`
	IssuedBy            string    `json:"issued_by"`
	Signature           string    `json:"signature"`
	MaxAssets           *int      `json:"max_assets,omitempty"`
	Customer            string    `json:"customer,omitempty"`
	HA                  *bool     `json:"ha,omitempty"`
}

func main() {
	max := 500
	ha := true
	// issued 40 days ago, valid 30 days → expired ~10 days ago
	issued := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(time.Second)
	p := payload{
		HardwareFingerprint: "*",
		Days:                30,
		IssuedAt:            issued,
		IssuedBy:            "KeepPAM Test",
		MaxAssets:           &max,
		Customer:            "Expired Test",
		HA:                  &ha,
	}
	p.Signature = sign(key, p)
	b, _ := json.Marshal(p)
	block, _ := aes.NewCipher(normalizeKey32(key))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)
	out := append(nonce, gcm.Seal(nil, nonce, b, nil)...)
	path := "/tmp/keeppam-expired.lic"
	os.WriteFile(path, out, 0o600)
	fmt.Printf("wrote %s (%d bytes)\n", path, len(out))

	f, raw, err := license.ParseEx2Blob(key, out, true)
	if err != nil {
		panic(err)
	}
	st := f.Evaluate(0, time.Now())
	fmt.Printf("customer=%s max_file=%d expires=%s expired=%v effective_max=%d hard=%v msg=%q\n",
		f.Customer, f.MaxAssets, f.Expires, st.Expired, st.MaxAssets, st.HardBlocked, st.Message)
	_ = raw
	_ = base64.StdEncoding
}

func sign(key string, p payload) string {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte(p.HardwareFingerprint))
	var days [4]byte
	binary.LittleEndian.PutUint32(days[:], p.Days)
	h.Write(days[:])
	h.Write([]byte(p.IssuedBy))
	h.Write([]byte(p.IssuedAt.UTC().Format("2006-01-02T15:04:05+00:00")))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func normalizeKey32(key string) []byte {
	b := []byte(key)
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out, b)
	return out
}
