package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const recordingsLastKey = "geo:recordings:last_sync"

// RecordingsConfig describes how recordings replicate between geo sites.
type RecordingsConfig struct {
	Mode           string // off | s3 | rsync
	LocalDir       string
	RecordingsBackend string // local | s3
	S3Bucket       string
	S3Prefix       string
	RsyncTarget    string // user@host:/path or /local/mirror
	RsyncSource    string // default LocalDir
}

func (c RecordingsConfig) SyncMode() string {
	m := strings.ToLower(strings.TrimSpace(c.Mode))
	if m == "off" || m == "" {
		if strings.ToLower(c.RecordingsBackend) == "s3" && c.S3Bucket != "" {
			return "s3"
		}
		if c.RsyncTarget != "" {
			return "rsync"
		}
		return "off"
	}
	return m
}

type RecordingsInventory struct {
	Files int64 `json:"files"`
	Bytes int64 `json:"bytes"`
}

type LastSync struct {
	At     time.Time `json:"at"`
	Mode   string    `json:"mode"`
	Files  int64     `json:"files,omitempty"`
	Bytes  int64     `json:"bytes,omitempty"`
	Error  string    `json:"error,omitempty"`
	Target string    `json:"target,omitempty"`
}

type RecordingsStatus struct {
	Mode        string              `json:"mode"`
	Inventory   RecordingsInventory `json:"inventory"`
	S3Bucket    string              `json:"s3_bucket,omitempty"`
	S3Prefix    string              `json:"s3_prefix,omitempty"`
	RsyncTarget string              `json:"rsync_target,omitempty"`
	LastSync    *LastSync           `json:"last_sync,omitempty"`
	Hint        string              `json:"hint"`
}

func ScanInventory(dir string) (RecordingsInventory, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return RecordingsInventory{}, fmt.Errorf("recordings dir empty")
	}
	var inv RecordingsInventory
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		inv.Files++
		inv.Bytes += info.Size()
		return nil
	})
	return inv, err
}

func RecordingsStatusOf(cfg RecordingsConfig, last *LastSync) (RecordingsStatus, error) {
	mode := cfg.SyncMode()
	src := cfg.LocalDir
	if strings.TrimSpace(cfg.RsyncSource) != "" {
		src = cfg.RsyncSource
	}
	st := RecordingsStatus{
		Mode:        mode,
		S3Bucket:    cfg.S3Bucket,
		S3Prefix:    cfg.S3Prefix,
		RsyncTarget: cfg.RsyncTarget,
		LastSync:    last,
	}
	switch mode {
	case "s3":
		st.Hint = "shared S3 bucket + bucket replication (MinIO/AWS CRR); both sites KEEPPAM_RECORDINGS_BACKEND=s3"
	case "rsync":
		st.Hint = "primary pushes via rsync; POST /admin/geo/recordings/sync or scripts/geo-recordings-sync.sh"
	default:
		st.Hint = "set KEEPPAM_GEO_RSYNC_TARGET or S3 bucket for geo recordings"
	}
	if src != "" {
		inv, err := ScanInventory(src)
		if err != nil && !os.IsNotExist(err) {
			return st, err
		}
		st.Inventory = inv
	}
	return st, nil
}

func LoadLastSync(ctx context.Context, rdb *redis.Client) *LastSync {
	if rdb == nil {
		return nil
	}
	b, err := rdb.Get(ctx, recordingsLastKey).Bytes()
	if err != nil {
		return nil
	}
	var ls LastSync
	if json.Unmarshal(b, &ls) == nil {
		return &ls
	}
	return nil
}

func SaveLastSync(ctx context.Context, rdb *redis.Client, ls LastSync, ttl time.Duration) {
	if rdb == nil {
		return
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	b, _ := json.Marshal(ls)
	_ = rdb.Set(ctx, recordingsLastKey, b, ttl).Err()
}

// RsyncOnce pushes source → target (primary → standby). Requires rsync on PATH.
func RsyncOnce(ctx context.Context, source, target string) (RecordingsInventory, error) {
	source = strings.TrimRight(strings.TrimSpace(source), "/") + "/"
	target = strings.TrimSpace(target)
	if source == "/" || target == "" {
		return RecordingsInventory{}, fmt.Errorf("invalid rsync paths")
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return RecordingsInventory{}, fmt.Errorf("rsync not found on PATH")
	}
	inv, _ := ScanInventory(strings.TrimRight(source, "/"))
	args := []string{"-az", "--partial", source, target}
	cmd := exec.CommandContext(ctx, "rsync", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return inv, fmt.Errorf("rsync: %w: %s", err, truncateOut(string(out), 400))
	}
	return inv, nil
}

func truncateOut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
