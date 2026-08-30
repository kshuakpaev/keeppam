package sessionsvc

import (
	"os"
	"path/filepath"
	"strings"
)

// IsGuacamoleRecording is true for HTML5 RDP/VNC .guac paths (guacenc / replay).
// Native mstsc captures (rdp-native, pcap) are not Guacamole streams.
func IsGuacamoleRecording(protocol, path string) bool {
	slash := filepath.ToSlash(path)
	if strings.Contains(slash, "/rdp-native/") {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap", ".rec", ".irdp":
		return false
	}
	return protocol == "rdp" || protocol == "vnc" || strings.Contains(slash, "/guac/")
}

// HasLocalGuacRecording reports whether guacd wrote a file at the session path.
func HasLocalGuacRecording(path string) bool {
	return largestGuacRecording(path) != ""
}

// LargestFileInDir returns the largest non-empty file under dir (one level of subdirs).
func LargestFileInDir(dir string) string {
	best := ""
	var bestSize int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if sub := LargestFileInDir(p); sub != "" {
				if st, err := os.Stat(sub); err == nil && st.Size() > bestSize {
					bestSize = st.Size()
					best = sub
				}
			}
			continue
		}
		low := strings.ToLower(e.Name())
		if strings.HasSuffix(low, ".ini") || strings.HasSuffix(low, ".tmp") || strings.HasSuffix(low, ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		if info.Size() > bestSize {
			bestSize = info.Size()
			best = p
		}
	}
	return best
}
