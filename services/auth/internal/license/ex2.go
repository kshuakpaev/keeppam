package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Ex2Payload matches the encrypted license blob from ../ex2 license-generator.
type Ex2Payload struct {
	HardwareFingerprint string `json:"hardware_fingerprint"`
	Days                uint32 `json:"days"`
	IssuedAt            time.Time `json:"issued_at"`
	IssuedBy            string `json:"issued_by"`
	Signature           string `json:"signature"`
	MaxAssets           *int   `json:"max_assets,omitempty"`
	SoftWarnPct         *int   `json:"soft_warn_pct,omitempty"`
	HA                  *bool  `json:"ha,omitempty"`
	Customer            string `json:"customer,omitempty"`
}

// DecryptEx2 decrypts nonce+ciphertext AES-256-GCM blob from ex2 generator.
func DecryptEx2(key string, blob []byte) (Ex2Payload, error) {
	if len(blob) < 13 {
		return Ex2Payload{}, fmt.Errorf("invalid license file format")
	}
	block, err := aes.NewCipher(normalizeKey32(key))
	if err != nil {
		return Ex2Payload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Ex2Payload{}, err
	}
	nonce := blob[:12]
	ciphertext := blob[12:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Ex2Payload{}, fmt.Errorf("decryption failed: %w", err)
	}
	var p Ex2Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Ex2Payload{}, fmt.Errorf("license json: %w", err)
	}
	return p, nil
}

func normalizeKey32(key string) []byte {
	b := []byte(key)
	if len(b) >= 32 {
		return b[:32]
	}
	out := make([]byte, 32)
	copy(out, b)
	return out
}

// VerifyEx2Signature checks SHA256 signature (same algorithm as ex2 generator).
func VerifyEx2Signature(key string, p Ex2Payload) bool {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write([]byte(p.HardwareFingerprint))
	var days [4]byte
	binary.LittleEndian.PutUint32(days[:], p.Days)
	h.Write(days[:])
	h.Write([]byte(p.IssuedBy))
	h.Write([]byte(p.IssuedAt.UTC().Format(time.RFC3339)))
	got := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return got == p.Signature
}

// HardwareFingerprint returns a stable host id (compatible with ex2/core).
func HardwareFingerprint() (string, error) {
	var parts []string
	if macs, err := macAddresses(); err == nil {
		parts = append(parts, macs...)
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		parts = append(parts, "hostname:"+host)
	}
	if cpu, err := cpuInfo(); err == nil && cpu != "" {
		parts = append(parts, "cpu:"+cpu)
	}
	if disk, err := diskInfo(); err == nil && disk != "" {
		parts = append(parts, "disk:"+disk)
	}
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			id := strings.TrimSpace(string(b))
			if id != "" {
				parts = append(parts, "machine_id:"+id)
				break
			}
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no hardware components")
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func macAddresses() ([]string, error) {
	out, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		out, err = exec.Command("ifconfig").Output()
		if err != nil {
			return nil, err
		}
	}
	var macs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "link/ether") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				macs = append(macs, "mac:"+fields[1])
			}
		} else if strings.Contains(line, "ether") || strings.Contains(line, "HWaddr") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "ether" || f == "HWaddr" {
					if i+1 < len(fields) {
						macs = append(macs, "mac:"+fields[i+1])
					}
				}
			}
		}
	}
	return macs, nil
}

func cpuInfo() (string, error) {
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				if _, v, ok := strings.Cut(line, ":"); ok {
					return strings.TrimSpace(v), nil
				}
			}
		}
	}
	out, err := exec.Command("lscpu").Output()
	if err != nil {
		return "unknown", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Model name:") {
			if _, v, ok := strings.Cut(line, ":"); ok {
				return strings.TrimSpace(v), nil
			}
		}
	}
	return "unknown", nil
}

func diskInfo() (string, error) {
	out, err := exec.Command("lsblk", "-o", "UUID,NAME", "-n").Output()
	if err == nil {
		var uuids []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] != "NAME" && fields[0] != "" {
				uuids = append(uuids, fields[0])
			}
		}
		if len(uuids) > 0 {
			sort.Strings(uuids)
			return strings.Join(uuids, ","), nil
		}
	}
	out, err = exec.Command("findmnt", "-n", "-o", "UUID", "/").Output()
	if err == nil {
		u := strings.TrimSpace(string(out))
		if u != "" {
			return u, nil
		}
	}
	return "unknown", nil
}

// ParseEx2Blob validates encrypted license and maps to KeepPAM File.
func ParseEx2Blob(key string, blob []byte, skipHW bool) (File, Ex2Payload, error) {
	p, err := DecryptEx2(key, blob)
	if err != nil {
		return File{}, Ex2Payload{}, err
	}
	if !VerifyEx2Signature(key, p) {
		return File{}, p, fmt.Errorf("invalid license signature")
	}
	if !skipHW && p.HardwareFingerprint != "*" {
		cur, err := HardwareFingerprint()
		if err != nil {
			return File{}, p, fmt.Errorf("hardware fingerprint: %w", err)
		}
		if p.HardwareFingerprint != cur {
			return File{}, p, fmt.Errorf("hardware fingerprint mismatch (license=%s, host=%s)", p.HardwareFingerprint, cur)
		}
	}
	expires := p.IssuedAt.UTC().Add(time.Duration(p.Days) * 24 * time.Hour)
	f := File{
		Issued:      p.IssuedAt.UTC().Format("2006-01-02"),
		Customer:    strings.TrimSpace(p.Customer),
		MaxAssets:   100,
		SoftWarnPct: 90,
		HA:          true,
		Expires:     expires.UTC().Format("2006-01-02"),
		Source:      "ex2",
	}
	if p.Customer == "" && p.IssuedBy != "" {
		f.Customer = p.IssuedBy
	}
	if p.MaxAssets != nil && *p.MaxAssets > 0 {
		f.MaxAssets = *p.MaxAssets
	}
	if p.SoftWarnPct != nil && *p.SoftWarnPct > 0 && *p.SoftWarnPct <= 100 {
		f.SoftWarnPct = *p.SoftWarnPct
	}
	if p.HA != nil {
		f.HA = *p.HA
	}
	return f, p, nil
}

// LoadAny reads JSON entitlement or ex2 encrypted blob from path.
func LoadAny(path, encKey string, skipHW bool) (File, error) {
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
	trim := strings.TrimSpace(string(b))
	if strings.HasPrefix(trim, "{") {
		var f File
		if err := json.Unmarshal(b, &f); err != nil {
			return File{}, fmt.Errorf("license.json: %w", err)
		}
		f.Source = path
		normalizeFile(&f)
		return f, nil
	}
	raw := b
	if dec, err := base64.StdEncoding.DecodeString(trim); err == nil && len(dec) > 12 {
		raw = dec
	}
	f, _, err := ParseEx2Blob(encKey, raw, skipHW)
	if err != nil {
		return File{}, err
	}
	f.Source = path
	return f, nil
}

func normalizeFile(f *File) {
	if f.MaxAssets <= 0 {
		f.MaxAssets = 100
	}
	if f.SoftWarnPct <= 0 || f.SoftWarnPct > 100 {
		f.SoftWarnPct = 90
	}
	if f.Issued == "" {
		f.Issued = time.Now().UTC().Format("2006-01-02")
	}
}
