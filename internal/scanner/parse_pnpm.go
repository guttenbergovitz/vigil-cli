package scanner

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParsePnpmLock parses pnpm-lock.yaml format.
func ParsePnpmLock(r io.Reader) (*Dependencies, error) {
	var lockFile struct {
		Packages map[string]struct {
			Dev bool `yaml:"dev"`
		} `yaml:"packages"`
	}

	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lockFile); err != nil {
		return nil, fmt.Errorf("parse pnpm lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for pkgPath := range lockFile.Packages {
		// pnpm format: "package-name@1.0.0" or "package-name@1.0.0/sub/dependency"
		// We need to extract name@version
		parts := strings.SplitN(pkgPath, "@", 2)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		// Extract version (everything after @ before next / if any)
		versionPart := strings.SplitN(parts[1], "/", 2)
		version := versionPart[0]

		if version == "" {
			continue
		}

		isDev := lockFile.Packages[pkgPath].Dev

		if isDev {
			deps.Development[name] = version
		} else {
			deps.Production[name] = version
		}
	}

	return deps, nil
}

// ParseYarnLock parses yarn.lock format (v1 and v2+).
func ParseYarnLock(r io.Reader) (*Dependencies, error) {
	// Yarn.lock is not YAML but custom format
	// For now, return placeholder - proper implementation needed
	return &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}, fmt.Errorf("yarn.lock parsing not yet implemented")
}
