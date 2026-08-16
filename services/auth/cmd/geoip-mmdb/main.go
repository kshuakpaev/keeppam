package main

import (
	"fmt"
	"os"

	"github.com/keeppam/auth/internal/geoip"
)

func main() {
	out := "country-demo.mmdb"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := geoip.WriteDemoMMDB(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote", out)
}
