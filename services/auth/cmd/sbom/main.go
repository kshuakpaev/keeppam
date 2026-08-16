package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/keeppam/auth/internal/sbom"
)

func main() {
	bom, err := sbom.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bom); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
