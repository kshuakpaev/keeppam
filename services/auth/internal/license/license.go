package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	ModelAssets = "assets"
	ModelUsers  = "users"
	ModelBoth   = "both"
)

// File is the on-disk KeepPAM entitlement (T-52). Not a cryptographic license.
type File struct {
	Issued      string `json:"issued"`
	Customer    string `json:"customer,omitempty"`
	Model       string `json:"model,omitempty"` // assets | users | both; inferred if empty
	MaxAssets   int    `json:"max_assets"`
	MaxUsers    int    `json:"max_users"`     // concurrent sessions (pending+active)
	SoftWarnPct int    `json:"soft_warn_pct"` // 1..100, default 90
	HA          bool   `json:"ha"`
	AICopilot   bool   `json:"ai_copilot"`
	Expires     string `json:"expires,omitempty"` // YYYY-MM-DD optional
	Source      string `json:"-"`
}

// Status is returned to UI / API.
type Status struct {
	Issued            string `json:"issued"`
	Customer          string `json:"customer,omitempty"`
	Model             string `json:"model"`
	MaxAssets         int    `json:"max_assets"`
	MaxUsers          int    `json:"max_users"`
	AssetCount        int    `json:"asset_count"`
	UserCount         int    `json:"user_count"`
	SoftWarnAt        int    `json:"soft_warn_at"`
	SoftWarnAtUsers   int    `json:"soft_warn_at_users"`
	LimitsAssets      bool   `json:"limits_assets"`
	LimitsUsers       bool   `json:"limits_users"`
	HA                bool   `json:"ha"`
	AICopilot         bool   `json:"ai_copilot"`
	Expires           string `json:"expires,omitempty"`
	Expired           bool   `json:"expired"`
	SoftWarn          bool   `json:"soft_warn"`
	HardBlocked       bool   `json:"hard_blocked"`
	HardBlockedAssets bool   `json:"hard_blocked_assets"`
	HardBlockedUsers  bool   `json:"hard_blocked_users"`
	Source            string `json:"source"`
	Message           string `json:"message,omitempty"`
	Format            string `json:"format,omitempty"` // json | ex2
	HostFingerprint   string `json:"host_fingerprint,omitempty"`
	IssuedBy          string `json:"issued_by,omitempty"`
	DaysRemaining     *int   `json:"days_remaining,omitempty"`
}

// CapError is a hard entitlement deny (asset create or new session).
type CapError struct {
	Message string
}

func (e *CapError) Error() string {
	if e == nil || e.Message == "" {
		return "license limit"
	}
	return e.Message
}

func IsCap(err error) bool {
	var c *CapError
	return errors.As(err, &c)
}

// GraceMaxAssets is the hard cap with no license file or after expires (assets SKU).
const GraceMaxAssets = 5

// GraceMaxUsers is the concurrent-session cap after a users/both license expires.
const GraceMaxUsers = 5

// ExpiredMaxAssets is an alias used when the license is past its expires date.
const ExpiredMaxAssets = GraceMaxAssets

// DefaultFile is used when no license file is present (unlicensed grace: 5 assets).
func DefaultFile() File {
	return File{
		Issued:      time.Now().UTC().Format("2006-01-02"),
		Customer:    "unlicensed",
		Model:       ModelAssets,
		MaxAssets:   GraceMaxAssets,
		SoftWarnPct: 90,
		HA:          true,
		AICopilot:   true,
		Source:      "default",
	}
}

// IsUnlicensed is true when no entitlement file was loaded (default / missing path).
func (f File) IsUnlicensed() bool {
	s := strings.TrimSpace(f.Source)
	return s == "" || s == "default" || strings.HasPrefix(s, "missing:")
}

// ResolvedModel is assets, users or both.
func (f File) ResolvedModel() string {
	return InferModel(f.Model, f.MaxAssets, f.MaxUsers)
}

// InferModel maps explicit model or infers from which caps are set.
func InferModel(model string, maxAssets, maxUsers int) string {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case ModelAssets, ModelUsers, ModelBoth:
		return strings.ToLower(strings.TrimSpace(model))
	}
	if maxUsers > 0 && maxAssets > 0 {
		return ModelBoth
	}
	if maxUsers > 0 {
		return ModelUsers
	}
	return ModelAssets
}

func (f File) limitsAssets(now time.Time) bool {
	if f.IsUnlicensed() {
		return true
	}
	if f.IsExpired(now) {
		return f.ResolvedModel() != ModelUsers
	}
	return f.ResolvedModel() != ModelUsers
}

func (f File) limitsUsers(now time.Time) bool {
	if f.IsUnlicensed() {
		return false
	}
	if f.IsExpired(now) {
		return f.ResolvedModel() != ModelAssets
	}
	return f.ResolvedModel() != ModelAssets
}

// EffectiveMaxAssets is MaxAssets, 0 = unlimited, or grace when expired / unlicensed.
func (f File) EffectiveMaxAssets(now time.Time) int {
	if !f.limitsAssets(now) {
		return 0
	}
	if f.IsExpired(now) || f.IsUnlicensed() {
		return GraceMaxAssets
	}
	if f.MaxAssets <= 0 {
		return GraceMaxAssets
	}
	return f.MaxAssets
}

// EffectiveMaxUsers is concurrent-session cap, 0 = unlimited.
func (f File) EffectiveMaxUsers(now time.Time) int {
	if !f.limitsUsers(now) {
		return 0
	}
	if f.IsExpired(now) {
		return GraceMaxUsers
	}
	if f.MaxUsers <= 0 {
		return GraceMaxUsers
	}
	return f.MaxUsers
}

// VisibleLimit returns how many assets are shown in lists under grace (0 = no restriction).
func (f File) VisibleLimit(now time.Time) int {
	if !f.limitsAssets(now) {
		return 0
	}
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
	normalizeFile(&f)
	return f, nil
}

func (f File) SoftWarnAt() int {
	return SoftWarnAtFor(f.EffectiveMaxAssets(time.Now()), f.SoftWarnPct)
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
	end := t.UTC().Add(24*time.Hour - time.Nanosecond)
	return now.UTC().After(end)
}

// Evaluate compares current usage to entitlement.
func (f File) Evaluate(assetCount, sessionCount int, now time.Time) Status {
	expired := f.IsExpired(now)
	unlicensed := f.IsUnlicensed()
	model := f.ResolvedModel()
	maxA := f.EffectiveMaxAssets(now)
	maxU := f.EffectiveMaxUsers(now)
	limA := f.limitsAssets(now)
	limU := f.limitsUsers(now)
	warnA := SoftWarnAtFor(maxA, f.SoftWarnPct)
	warnU := SoftWarnAtFor(maxU, f.SoftWarnPct)
	st := Status{
		Issued:          f.Issued,
		Customer:        f.Customer,
		Model:           model,
		MaxAssets:       maxA,
		MaxUsers:        maxU,
		AssetCount:      assetCount,
		UserCount:       sessionCount,
		SoftWarnAt:      warnA,
		SoftWarnAtUsers: warnU,
		LimitsAssets:    limA,
		LimitsUsers:     limU,
		HA:              f.HA,
		AICopilot:       f.AllowAICopilot(),
		Expires:         f.Expires,
		Expired:         expired,
		Source:          f.Source,
	}
	var parts []string
	if limA {
		blocked, warn, msg := dimStatus("активов", assetCount, maxA, warnA, expired, unlicensed, "создание заблокировано")
		st.HardBlockedAssets = blocked
		if warn {
			st.SoftWarn = true
		}
		if msg != "" {
			parts = append(parts, msg)
		}
	}
	if limU {
		blocked, warn, msg := dimStatus("сессий", sessionCount, maxU, warnU, expired, unlicensed, "новые подключения заблокированы")
		st.HardBlockedUsers = blocked
		if warn {
			st.SoftWarn = true
		}
		if msg != "" {
			parts = append(parts, msg)
		}
	}
	st.HardBlocked = st.HardBlockedAssets || st.HardBlockedUsers
	st.Message = strings.Join(parts, "; ")
	return st
}

func dimStatus(noun string, count, max, warnAt int, expired, unlicensed bool, blockVerb string) (blocked, warn bool, msg string) {
	if max <= 0 {
		return false, false, ""
	}
	prefix := ""
	switch {
	case expired:
		prefix = "лицензия истекла — "
	case unlicensed:
		prefix = "лицензия не установлена — "
	}
	if count >= max {
		return true, true, fmt.Sprintf("%sлимит %s %d/%d — %s", prefix, noun, count, max, blockVerb)
	}
	if count >= warnAt {
		if prefix != "" {
			return false, true, fmt.Sprintf("%sдоступно до %d %s (%d/%d)", prefix, max, noun, count, max)
		}
		return false, true, fmt.Sprintf("приближение к лимиту %s %d/%d", noun, count, max)
	}
	if expired || unlicensed {
		return false, true, fmt.Sprintf("%sдоступно до %d %s (%d/%d)", prefix, max, noun, count, max)
	}
	return false, false, ""
}

// SoftWarnAtFor computes soft-warn threshold for a given max.
func SoftWarnAtFor(maxAssets, softWarnPct int) int {
	if maxAssets <= 0 {
		return 0
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

// AllowCreate is false when the assets dimension is at hard cap.
func (f File) AllowCreate(assetCount int, now time.Time) error {
	st := f.Evaluate(assetCount, 0, now)
	if st.HardBlockedAssets {
		return &CapError{Message: st.Message}
	}
	return nil
}

// AllowSession is false when the concurrent-session dimension is at hard cap.
func (f File) AllowSession(sessionCount int, now time.Time) error {
	st := f.Evaluate(0, sessionCount, now)
	if st.HardBlockedUsers {
		return &CapError{Message: st.Message}
	}
	return nil
}

// AllowAICopilot is true for unlicensed/dev grace and for entitlements with ai_copilot.
func (f File) AllowAICopilot() bool {
	if f.IsUnlicensed() {
		return true
	}
	return f.AICopilot
}
