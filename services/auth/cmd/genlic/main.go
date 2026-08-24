// One-off: generate ex2 license blob (same key/algorithm as ../ex2 generator).
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
)

const key = "your-32-byte-encryption-key-change-me!!"

type payload struct {
	HardwareFingerprint string `json:"hardware_fingerprint"`
	Days                uint32 `json:"days"`
	IssuedAt            time.Time `json:"issued_at"`
	IssuedBy            string `json:"issued_by"`
	Signature           string `json:"signature"`
	MaxAssets           *int   `json:"max_assets,omitempty"`
	Customer            string `json:"customer,omitempty"`
	HA                  *bool  `json:"ha,omitempty"`
}

func main() {
	max := 500
	ha := true
	issued := time.Now().UTC().Truncate(time.Second)
	p := payload{
		HardwareFingerprint: "*",
		Days:                365,
		IssuedAt:            issued,
		IssuedBy:            "KeepPAM Auto",
		MaxAssets:           &max,
		Customer:            "KeepPAM Lab",
		HA:                  &ha,
	}
	p.Signature = sign(key, p)

	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	k := normalizeKey32(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	out := append(nonce, gcm.Seal(nil, nonce, b, nil)...)

	path := "/tmp/keeppam-dev.lic"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(out))
	fmt.Printf("base64: %s\n", base64.StdEncoding.EncodeToString(out))
}

func ex2IssuedAtString(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05+00:00")
}

func sign(key string, p payload) string {
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

func normalizeKey32(key string) []byte {
	b := []byte(key)
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out, b)
	return out
}
