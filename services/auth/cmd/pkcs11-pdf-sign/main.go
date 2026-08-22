// pkcs11-pdf-sign — demo PKCS#11 helper for PAdES (lab / acceptance).
// Reads base64 SHA-256 digest on stdin; writes base64 RSA PKCS#1 v1.5 signature to stdout.
// Env: KEEPPAM_PDF_KEY_FILE (PEM RSA key) or KEEPPAM_PDF_PKCS11_PIN + real HSM module via partner helper.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	keyFile := os.Getenv("KEEPPAM_PDF_KEY_FILE")
	if keyFile == "" {
		fmt.Fprintln(os.Stderr, "KEEPPAM_PDF_KEY_FILE required for demo pkcs11-pdf-sign")
		os.Exit(2)
	}
	tlsCert, err := tls.LoadX509KeyPair(keyFile, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "need RSA private key")
		os.Exit(1)
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hash, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hash)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(base64.StdEncoding.EncodeToString(sig))
}
