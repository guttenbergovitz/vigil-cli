package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Dependencies holds parsed production and development dependencies.
type Dependencies struct {
	Production  map[string]string
	Development map[string]string
}

// ParseNPMLock parses npm package-lock.json format.
func ParseNPMLock(r io.Reader) (*Dependencies, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse npm lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for pkgPath, pkg := range lock.Packages {
		// Skip root package
		if pkgPath == "" || pkg.Version == "" {
			continue
		}

		// Extract package name from path (e.g., "node_modules/express" -> "express")
		name := filepath.Base(pkgPath)

		if pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// FindLockFile searches for supported lock files in the given directory.
// Returns the filename of the first found lock file, or error if none found.
func FindLockFile(dir string) (string, error) {
	candidates := []string{
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
	}

	for _, candidate := range candidates {
		path := filepath.Join(dir, candidate)
		if _, err := os.Stat(path); err == nil {
			return candidate, nil
		}
	}

	return "", errors.New("no supported lock file found (package-lock.json, yarn.lock, pnpm-lock.yaml)")
}

// ParsePackageJSON extracts name and version from package.json.
func ParsePackageJSON(r io.Reader) (map[string]interface{}, error) {
	var pkg map[string]interface{}

	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	return pkg, nil
}
