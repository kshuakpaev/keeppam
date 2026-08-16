//go:build !boringcrypto && !fips140

package fips

func taggedBackend() string { return "" }
