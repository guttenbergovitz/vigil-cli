package lockfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestCachePersistence(t *testing.T) {
	tmpdir := t.TempDir()
	cachePath := filepath.Join(tmpdir, ".vigil.cache")

	result := &types.ScanResult{
		Version:      1,
		ProjectPath:  "/test/project",
		ScannedAt:    time.Now().UTC(),
		LockFile:     "package-lock.json",
		LockFileHash: "abc123def456",
		Dependencies: []types.Dependency{
			{
				Name:    "express",
				Version: "4.18.0",
				Type:    types.Production,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:        "CVE-2024-1234",
						Summary:   "XSS vulnerability",
						Severity:  types.Medium,
						RiskScore: 45,
					},
				},
			},
		},
		CriticalVulns: 0,
		HighVulns:     0,
		MediumVulns:   1,
		LowVulns:      0,
	}

	// Save
	err := SaveCache(cachePath, result)
	if err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}

	// Load
	loaded, err := LoadCache(cachePath)
	if err != nil {
		t.Fatalf("LoadCache() error = %v", err)
	}

	// Verify content
	if loaded.ProjectPath != result.ProjectPath {
		t.Errorf("ProjectPath mismatch: got %s, want %s", loaded.ProjectPath, result.ProjectPath)
	}
	if loaded.LockFileHash != result.LockFileHash {
		t.Errorf("LockFileHash mismatch: got %s, want %s", loaded.LockFileHash, result.LockFileHash)
	}
	if len(loaded.Dependencies) != len(result.Dependencies) {
		t.Errorf("Dependencies count mismatch: got %d, want %d", len(loaded.Dependencies), len(result.Dependencies))
	}
	if len(loaded.Dependencies) > 0 && len(loaded.Dependencies[0].Vulnerabilities) > 0 {
		if loaded.Dependencies[0].Vulnerabilities[0].ID != "CVE-2024-1234" {
			t.Errorf("CVE ID mismatch in loaded cache")
		}
	}
}

func TestCacheInvalidation(t *testing.T) {
	// Test that cache is invalid when lock file hash changes
	oldHash := "old-hash-123"
	newHash := "new-hash-456"

	isValid := IsCacheValid(oldHash, newHash)
	if isValid {
		t.Errorf("cache should be invalid when hashes differ")
	}

	isValid = IsCacheValid(newHash, newHash)
	if !isValid {
		t.Errorf("cache should be valid when hashes match")
	}
}

func TestCacheFileNotFound(t *testing.T) {
	cachePath := "/nonexistent/path/.vigil.cache"
	_, err := LoadCache(cachePath)
	if err == nil {
		t.Errorf("LoadCache() should error for nonexistent file")
	}
}
