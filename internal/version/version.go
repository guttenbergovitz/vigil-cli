package version

import (
	"fmt"
	"runtime/debug"
)

// Build-time variables injected via ldflags
var (
	// Version is the git tag (e.g., "v1.0.0")
	Version = "dev"
	// Commit is the git commit hash
	Commit = "unknown"
	// Date is the build date
	Date = "unknown"
)

// Get returns the full version string.
func Get() string {
	if Version == "dev" {
		// Try to get version from build info (when installed via go install)
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				Version = info.Main.Version
			}
		}
	}

	if Commit == "unknown" {
		return Version
	}

	if len(Commit) > 7 {
		Commit = Commit[:7]
	}

	return fmt.Sprintf("%s (%s)", Version, Commit)
}

// GetFull returns version with build date.
func GetFull() string {
	base := Get()
	if Date != "unknown" {
		return fmt.Sprintf("%s built on %s", base, Date)
	}
	return base
}
