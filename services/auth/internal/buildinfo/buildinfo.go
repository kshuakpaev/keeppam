// Package buildinfo holds product version injected at link time (-ldflags).
package buildinfo

// Version is KeepPAM release version (semver from ./VERSION).
var Version = "dev"

// BuildTime is UTC timestamp of the binary build (optional).
var BuildTime = ""
