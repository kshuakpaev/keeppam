package fips

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Backend is "boringcrypto", "fips140", or "go" (standard library).
func Backend() string {
	if b := taggedBackend(); b != "" {
		return b
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "go"
	}
	for _, s := range info.Settings {
		if s.Key != "GOEXPERIMENT" {
			continue
		}
		v := strings.ToLower(s.Value)
		if strings.Contains(v, "boringcrypto") {
			return "boringcrypto"
		}
		if strings.Contains(v, "fips140") {
			return "fips140"
		}
	}
	return "go"
}

func Enabled() bool {
	b := Backend()
	return b == "boringcrypto" || b == "fips140"
}

func Enforce(required bool) error {
	if !required {
		return nil
	}
	if Enabled() {
		return nil
	}
	return fmt.Errorf("KEEPPAM_FIPS_REQUIRED=true but binary is not a FIPS module (backend=%s); rebuild with GOEXPERIMENT=boringcrypto (Go 1.23) or GOFIPS140=on (Go 1.24+), see docs/fips-sbom.txt", Backend())
}

func GoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.GoVersion == "" {
		return ""
	}
	return info.GoVersion
}

func CGOEnabled() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "CGO_ENABLED" {
			return s.Value
		}
	}
	return ""
}
