package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/keeppam/auth/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "wrap":
		os.Exit(runWrap(os.Args[2:]))
	case "unwrap":
		os.Exit(runUnwrap(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `pkcs11-token — software PKCS#11 token for KeepPAM data key

  init   --pin PIN --out TOKEN [--label KeepPAM] [--key-label keeppam-kek]
  wrap   --pin PIN --token TOKEN [--dek-b64 B64 | --dek-file PATH]
  unwrap --pin PIN --token TOKEN --ciphertext B64

init writes a PIN-locked KEK. wrap prints KEEPPAM_KMS_CIPHERTEXT (and the DEK once).
See docs/pkcs11.txt.
`)
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	pin := fs.String("pin", "", "")
	out := fs.String("out", "", "")
	label := fs.String("label", "KeepPAM", "")
	keyLabel := fs.String("key-label", "keeppam-kek", "")
	_ = fs.Parse(args)
	if *pin == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "init: --pin and --out required")
		return 2
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := crypto.InitPKCS11Token(*out, *pin, *label, *keyLabel, kek); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s (KEK stays in token)\n", *out)
	return 0
}

func runWrap(args []string) int {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	pin := fs.String("pin", "", "")
	token := fs.String("token", "", "")
	dekB64 := fs.String("dek-b64", "", "")
	dekFile := fs.String("dek-file", "", "")
	_ = fs.Parse(args)
	if *pin == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "wrap: --pin and --token required")
		return 2
	}
	kek, err := crypto.UnlockPKCS11Token(*token, *pin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dek, err := loadDEK(*dekB64, *dekFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	wrapped, err := crypto.WrapDEKWithKEK(kek, dek)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("KEEPPAM_KMS_CIPHERTEXT=%s\n", base64.StdEncoding.EncodeToString(wrapped))
	if *dekB64 == "" && *dekFile == "" {
		fmt.Fprintf(os.Stderr, "generated DEK (store only if migrating): %s\n", base64.StdEncoding.EncodeToString(dek))
	}
	return 0
}

func runUnwrap(args []string) int {
	fs := flag.NewFlagSet("unwrap", flag.ExitOnError)
	pin := fs.String("pin", "", "")
	token := fs.String("token", "", "")
	ct := fs.String("ciphertext", "", "")
	_ = fs.Parse(args)
	if *pin == "" || *token == "" || *ct == "" {
		fmt.Fprintln(os.Stderr, "unwrap: --pin --token --ciphertext required")
		return 2
	}
	p := crypto.PKCS11Provider{TokenFile: *token, PIN: *pin, Ciphertext: *ct}
	dek, err := p.Load(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(base64.StdEncoding.EncodeToString(dek))
	return 0
}

func loadDEK(b64, file string) ([]byte, error) {
	if b64 != "" && file != "" {
		return nil, fmt.Errorf("use either --dek-b64 or --dek-file")
	}
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		s := strings.TrimSpace(string(raw))
		if len(raw) == 32 && !strings.Contains(s, "\n") {
			return raw, nil
		}
		b64 = s
	}
	if b64 != "" {
		dek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(dek) != 32 {
			return nil, fmt.Errorf("DEK must be base64 of 32 bytes")
		}
		return dek, nil
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}
