package winrm

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// LocalUser is a Windows local SAM account discovered via WinRM or SSH fallback.
type LocalUser struct {
	Name       string
	Enabled    bool
	SID        string
	Privileged bool
	Source     string // winrm | sam_ssh
}

const discoverPSScript = `$ErrorActionPreference='SilentlyContinue';` +
	`$users=@();` +
	`if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {` +
	`Get-LocalUser | ForEach-Object { $users += [pscustomobject]@{Name=$_.Name;Enabled=$_.Enabled;SID=$_.SID.Value} }` +
	`} else {` +
	`net user | Select-Object -Skip 2 | ForEach-Object { if ($_ -match '^\s*(\S+)') { $users += [pscustomobject]@{Name=$matches[1];Enabled=$true;SID=''} } }` +
	`};` +
	`$admins=@();` +
	`if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {` +
	`Get-LocalGroupMember -Group Administrators | ForEach-Object { $admins += $_.Name }` +
	`} else {` +
	`net localgroup Administrators | Select-Object -Skip 6 | ForEach-Object { if ($_ -and $_.Trim()) { $admins += $_.Trim() } }` +
	`};` +
	`@{users=$users;admins=$admins}|ConvertTo-Json -Compress -Depth 5`

type psPayload struct {
	Users []struct {
		Name    string `json:"Name"`
		Enabled *bool  `json:"Enabled"`
		SID     string `json:"SID"`
	} `json:"users"`
	Admins []string `json:"admins"`
}

// ParseDiscoverJSON parses PowerShell JSON from discoverPSScript.
func ParseDiscoverJSON(raw string) ([]LocalUser, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty winrm output")
	}
	// Strip BOM / CLIXML noise
	if i := strings.Index(raw, "{"); i > 0 {
		raw = raw[i:]
	}
	var p psPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return parseNetUserFallback(raw)
	}
	adminSet := map[string]struct{}{}
	for _, a := range p.Admins {
		a = normalizeWinName(a)
		if a != "" {
			adminSet[strings.ToLower(a)] = struct{}{}
		}
	}
	var out []LocalUser
	seen := map[string]struct{}{}
	for _, u := range p.Users {
		name := strings.TrimSpace(u.Name)
		if name == "" || isSkippedWinUser(name) {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		if !enabled {
			continue
		}
		priv := isWinPrivileged(name, u.SID, adminSet)
		out = append(out, LocalUser{Name: name, Enabled: enabled, SID: u.SID, Privileged: priv, Source: "winrm"})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no local users parsed")
	}
	return out, nil
}

var netUserLine = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_.$-]+)\s`)

func parseNetUserFallback(raw string) ([]LocalUser, error) {
	var out []LocalUser
	seen := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.Contains(strings.ToLower(line), "command completed") {
			continue
		}
		m := netUserLine.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		name := m[1]
		if isSkippedWinUser(name) {
			continue
		}
		if _, ok := seen[strings.ToLower(name)]; ok {
			continue
		}
		seen[strings.ToLower(name)] = struct{}{}
		out = append(out, LocalUser{Name: name, Enabled: true, Privileged: isWinPrivileged(name, "", nil), Source: "winrm"})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parse winrm output failed")
	}
	return out, nil
}

// ParseSAMNetUser parses `net user` + optional administrators block from SSH.
func ParseSAMNetUser(netUserOut, adminOut string) ([]LocalUser, error) {
	adminSet := map[string]struct{}{}
	for _, line := range strings.Split(adminOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.Contains(strings.ToLower(line), "command completed") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		name := normalizeWinName(parts[0])
		if name != "" {
			adminSet[strings.ToLower(name)] = struct{}{}
		}
	}
	users, err := parseNetUserFallback(netUserOut)
	if err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Source = "sam_ssh"
		users[i].Privileged = isWinPrivileged(users[i].Name, users[i].SID, adminSet)
	}
	return users, nil
}

func normalizeWinName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func isSkippedWinUser(name string) bool {
	switch strings.ToLower(name) {
	case "user", "users", "accounts", "the", "username", "comment", "name", "successfully", "members":
		return true
	default:
		return false
	}
}

func isWinPrivileged(name, sid string, admins map[string]struct{}) bool {
	n := strings.ToLower(normalizeWinName(name))
	if n == "administrator" || n == "admin" {
		return true
	}
	if strings.HasSuffix(sid, "-500") {
		return true
	}
	if admins != nil {
		if _, ok := admins[n]; ok {
			return true
		}
		if _, ok := admins["builtin\\"+n]; ok {
			return true
		}
	}
	return false
}

// DiscoverScript returns the embedded PowerShell for tests/docs.
func DiscoverScript() string { return discoverPSScript }
