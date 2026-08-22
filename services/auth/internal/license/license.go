package license

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// File is the on-disk KeepPAM entitlement (T-52). Not a cryptographic license.
type File struct {
	Issued      string `json:"issued"`
	Customer    string `json:"customer,omitempty"`
	MaxAssets   int    `json:"max_assets"`
	SoftWarnPct int    `json:"soft_warn_pct"` // 1..100, default 90
	HA          bool   `json:"ha"`
	Expires     string `json:"expires,omitempty"` // YYYY-MM-DD optional
	Source      string `json:"-"`
}

// Status is returned to UI / API.
type Status struct {
	Issued       string `json:"issued"`
	Customer     string `json:"customer,omitempty"`
	MaxAssets    int    `json:"max_assets"`
	AssetCount   int    `json:"asset_count"`
	SoftWarnAt   int    `json:"soft_warn_at"`
	HA           bool   `json:"ha"`
	Expires      string `json:"expires,omitempty"`
	Expired      bool   `json:"expired"`
	SoftWarn     bool   `json:"soft_warn"`
	HardBlocked  bool   `json:"hard_blocked"`
	Source              string `json:"source"`
	Message             string `json:"message,omitempty"`
	Format              string `json:"format,omitempty"` // json | ex2
	HostFingerprint     string `json:"host_fingerprint,omitempty"`
	IssuedBy            string `json:"issued_by,omitempty"`
	DaysRemaining       *int   `json:"days_remaining,omitempty"`
}

// DefaultFile is used when no license.json is present (contract baseline ≥100 ИС).
func DefaultFile() File {
	return File{
		Issued:      time.Now().UTC().Format("2006-01-02"),
		Customer:    "default",
		MaxAssets:   100,
		SoftWarnPct: 90,
		HA:          true,
		Source:      "default",
	}
}

// Load reads path; empty path or missing file → DefaultFile.
func Load(path string) (File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		f := DefaultFile()
		return f, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			f := DefaultFile()
			f.Source = "missing:" + path
			return f, nil
		}
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("license.json: %w", err)
	}
	f.Source = path
	if f.MaxAssets <= 0 {
		f.MaxAssets = 100
	}
	if f.SoftWarnPct <= 0 || f.SoftWarnPct > 100 {
		f.SoftWarnPct = 90
	}
	if f.Issued == "" {
		f.Issued = time.Now().UTC().Format("2006-01-02")
	}
	return f, nil
}

func (f File) SoftWarnAt() int {
	n := f.MaxAssets * f.SoftWarnPct / 100
	if n < 1 {
		n = 1
	}
	if n > f.MaxAssets {
		n = f.MaxAssets
	}
	return n
}

func (f File) IsExpired(now time.Time) bool {
	exp := strings.TrimSpace(f.Expires)
	if exp == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", exp)
	if err != nil {
		return false
	}
	// expires at end of that UTC day
	end := t.UTC().Add(24*time.Hour - time.Nanosecond)
	return now.UTC().After(end)
}

// Evaluate compares current active asset count to entitlement.
func (f File) Evaluate(assetCount int, now time.Time) Status {
	st := Status{
		Issued:     f.Issued,
		Customer:   f.Customer,
		MaxAssets:  f.MaxAssets,
		AssetCount: assetCount,
		SoftWarnAt: f.SoftWarnAt(),
		HA:         f.HA,
		Expires:    f.Expires,
		Expired:    f.IsExpired(now),
		Source:     f.Source,
	}
	if st.Expired {
		st.HardBlocked = true
		st.Message = "лицензия истекла — создание активов заблокировано"
		return st
	}
	if assetCount >= f.MaxAssets {
		st.HardBlocked = true
		st.SoftWarn = true
		st.Message = fmt.Sprintf("лимит активов %d/%d — создание заблокировано", assetCount, f.MaxAssets)
		return st
	}
	if assetCount >= st.SoftWarnAt {
		st.SoftWarn = true
		st.Message = fmt.Sprintf("приближение к лимиту активов %d/%d", assetCount, f.MaxAssets)
	}
	return st
}

// AllowCreate is false when hard cap or expired.
func (f File) AllowCreate(assetCount int, now time.Time) error {
	st := f.Evaluate(assetCount, now)
	if st.HardBlocked {
		return fmt.Errorf("%s", st.Message)
	}
	return nil
}
