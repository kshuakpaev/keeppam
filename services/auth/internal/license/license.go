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

// GraceMaxAssets is the hard cap with no license file or after expires.
const GraceMaxAssets = 5

// ExpiredMaxAssets is an alias used when the license is past its expires date.
const ExpiredMaxAssets = GraceMaxAssets

// DefaultFile is used when no license file is present (unlicensed grace: 5 assets).
func DefaultFile() File {
	return File{
		Issued:      time.Now().UTC().Format("2006-01-02"),
		Customer:    "unlicensed",
		MaxAssets:   GraceMaxAssets,
		SoftWarnPct: 90,
		HA:          true,
		Source:      "default",
	}
}

// IsUnlicensed is true when no entitlement file was loaded (default / missing path).
func (f File) IsUnlicensed() bool {
	s := strings.TrimSpace(f.Source)
	return s == "" || s == "default" || strings.HasPrefix(s, "missing:")
}

// EffectiveMaxAssets is MaxAssets, or GraceMaxAssets when expired / unlicensed.
func (f File) EffectiveMaxAssets(now time.Time) int {
	if f.IsExpired(now) || f.IsUnlicensed() {
		return GraceMaxAssets
	}
	if f.MaxAssets <= 0 {
		return GraceMaxAssets
	}
	return f.MaxAssets
}

// VisibleLimit returns how many assets are shown in lists under grace (0 = no restriction).
func (f File) VisibleLimit(now time.Time) int {
	if f.IsExpired(now) || f.IsUnlicensed() {
		return GraceMaxAssets
	}
	return 0
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
	return SoftWarnAtFor(f.MaxAssets, f.SoftWarnPct)
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
	expired := f.IsExpired(now)
	unlicensed := f.IsUnlicensed()
	max := f.EffectiveMaxAssets(now)
	warnAt := SoftWarnAtFor(max, f.SoftWarnPct)
	st := Status{
		Issued:     f.Issued,
		Customer:   f.Customer,
		MaxAssets:  max,
		AssetCount: assetCount,
		SoftWarnAt: warnAt,
		HA:         f.HA,
		Expires:    f.Expires,
		Expired:    expired,
		Source:     f.Source,
	}
	if expired {
		if assetCount >= max {
			st.HardBlocked = true
			st.SoftWarn = true
			st.Message = fmt.Sprintf("лицензия истекла — лимит %d/%d активов, создание заблокировано", assetCount, max)
			return st
		}
		st.SoftWarn = true
		st.Message = fmt.Sprintf("лицензия истекла — доступно до %d активов (%d/%d)", max, assetCount, max)
		return st
	}
	if unlicensed {
		if assetCount >= max {
			st.HardBlocked = true
			st.SoftWarn = true
			st.Message = fmt.Sprintf("лицензия не установлена — лимит %d/%d активов, создание заблокировано", assetCount, max)
			return st
		}
		st.SoftWarn = true
		st.Message = fmt.Sprintf("лицензия не установлена — доступно до %d активов (%d/%d)", max, assetCount, max)
		return st
	}
	if assetCount >= max {
		st.HardBlocked = true
		st.SoftWarn = true
		st.Message = fmt.Sprintf("лимит активов %d/%d — создание заблокировано", assetCount, max)
		return st
	}
	if assetCount >= warnAt {
		st.SoftWarn = true
		st.Message = fmt.Sprintf("приближение к лимиту активов %d/%d", assetCount, max)
	}
	return st
}

// SoftWarnAtFor computes soft-warn threshold for a given max.
func SoftWarnAtFor(maxAssets, softWarnPct int) int {
	if maxAssets <= 0 {
		maxAssets = GraceMaxAssets
	}
	if softWarnPct <= 0 || softWarnPct > 100 {
		softWarnPct = 90
	}
	n := maxAssets * softWarnPct / 100
	if n < 1 {
		n = 1
	}
	if n > maxAssets {
		n = maxAssets
	}
	return n
}

// AllowCreate is false when hard cap (including expired grace of ExpiredMaxAssets).
func (f File) AllowCreate(assetCount int, now time.Time) error {
	st := f.Evaluate(assetCount, now)
	if st.HardBlocked {
		return fmt.Errorf("%s", st.Message)
	}
	return nil
}
