package ueba

import (
	"net"
	"strings"
)

const (
	FactorNewIP     = "ueba_new_ip"
	FactorNewSubnet = "ueba_new_subnet"
	NewIPPoints     = 20
	NewSubnetPoints = 25
)

// ParseHostNet returns canonical host and subnet key (/24 IPv4, /64 IPv6).
func ParseHostNet(raw string) (host, netKey string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", "", false
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(24, 32)
		return v4.String(), v4.Mask(mask).String() + "/24", true
	}
	ip = ip.To16()
	mask := net.CIDRMask(64, 128)
	return ip.String(), ip.Mask(mask).String() + "/64", true
}

// NewIP is true when the user has a stable set of source hosts and this host is new.
func NewIP(baselineHosts int, seenHost bool) bool {
	return baselineHosts >= MinBaseline && !seenHost
}

// NewSubnet is true when the user has a stable set of source subnets and this one is new.
func NewSubnet(baselineNets int, seenNet bool) bool {
	return baselineNets >= MinBaseline && !seenNet
}
