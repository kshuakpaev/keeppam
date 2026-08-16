package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	Version      int         `json:"version"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []Tool     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
}

func Load() (BOM, error) {
	if path := strings.TrimSpace(os.Getenv("KEEPPAM_SBOM_FILE")); path != "" {
		return FromFile(path)
	}
	return FromRuntime(), nil
}

func FromFile(path string) (BOM, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return BOM{}, fmt.Errorf("sbom file: %w", err)
	}
	var bom BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return BOM{}, fmt.Errorf("sbom file: %w", err)
	}
	if !strings.EqualFold(bom.BOMFormat, "CycloneDX") {
		return BOM{}, fmt.Errorf("sbom file: expected CycloneDX, got %q", bom.BOMFormat)
	}
	if bom.SpecVersion == "" {
		bom.SpecVersion = "1.5"
	}
	if bom.Version == 0 {
		bom.Version = 1
	}
	return bom, nil
}

func FromRuntime() BOM {
	now := time.Now().UTC().Format(time.RFC3339)
	bom := BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: Metadata{
			Timestamp: now,
			Tools:     []Tool{{Vendor: "KeepPAM", Name: "keeppam-sbom", Version: "runtime"}},
		},
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return bom
	}
	mainName := info.Main.Path
	if mainName == "" {
		mainName = "keeppam-api"
	}
	mainVer := normalizeVer(info.Main.Version)
	main := Component{
		Type:    "application",
		Name:    mainName,
		Version: mainVer,
		PURL:    purl(mainName, mainVer),
		BOMRef:  mainName,
	}
	bom.Metadata.Component = &main
	seen := map[string]struct{}{mainName: {}}
	if info.GoVersion != "" {
		std := Component{Type: "library", Name: "std", Version: info.GoVersion, PURL: "pkg:golang/std@" + info.GoVersion, BOMRef: "std"}
		bom.Components = append(bom.Components, std)
	}
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		path, ver := d.Path, d.Version
		if d.Replace != nil {
			if d.Replace.Path != "" {
				path = d.Replace.Path
			}
			if d.Replace.Version != "" {
				ver = d.Replace.Version
			}
		}
		ver = normalizeVer(ver)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		bom.Components = append(bom.Components, Component{
			Type:    "library",
			Name:    path,
			Version: ver,
			PURL:    purl(path, ver),
			BOMRef:  path,
		})
	}
	return bom
}

func normalizeVer(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "(devel)" {
		return "devel"
	}
	return v
}

func purl(path, ver string) string {
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	if ver == "" || ver == "devel" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + ver
}
