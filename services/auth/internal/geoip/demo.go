package geoip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

const DemoDatabaseType = "KeepPAM-Country-Demo"

// DemoNetworks is a tiny stand-in for GeoLite2-Country (well-known DNS/anycast).
var DemoNetworks = []struct {
	CIDR    string
	ISOCode string
}{
	{"8.8.8.0/24", "US"},
	{"8.8.4.0/24", "US"},
	{"1.1.1.0/24", "US"},
	{"1.0.0.0/24", "US"},
	{"9.9.9.0/24", "US"},
	{"208.67.222.0/24", "US"},
	{"77.88.8.0/24", "RU"},
	{"5.255.255.0/24", "RU"},
	{"2001:4860:4860::/48", "US"},
}

func WriteDemoMMDB(path string) error {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: DemoDatabaseType,
		RecordSize:   28,
		IPVersion:    6,
		Description:  map[string]string{"en": "KeepPAM demo country DB — replace with MaxMind GeoLite2-Country in prod"},
	})
	if err != nil {
		return err
	}
	for _, n := range DemoNetworks {
		_, cidr, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			return fmt.Errorf("demo cidr %s: %w", n.CIDR, err)
		}
		rec := mmdbtype.Map{
			"country": mmdbtype.Map{
				"iso_code": mmdbtype.String(n.ISOCode),
			},
		}
		if err := w.Insert(cidr, rec); err != nil {
			return fmt.Errorf("demo insert %s: %w", n.CIDR, err)
		}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = w.WriteTo(f)
	return err
}
