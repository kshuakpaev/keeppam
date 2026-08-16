//go:build boringcrypto

package fips

func taggedBackend() string { return "boringcrypto" }
