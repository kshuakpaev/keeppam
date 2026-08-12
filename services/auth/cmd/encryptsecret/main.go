package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/keeppam/auth/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: encryptsecret <plaintext>")
		os.Exit(2)
	}
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("KEEPPAM_DATA_KEY"))
	if err != nil || len(raw) != 32 {
		fmt.Fprintln(os.Stderr, "KEEPPAM_DATA_KEY must be base64 of 32 bytes")
		os.Exit(1)
	}
	env, err := crypto.NewEnvelope(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := env.Encrypt([]byte(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(hex.EncodeToString(b))
}
