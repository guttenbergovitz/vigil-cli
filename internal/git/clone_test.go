package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"https://github.com/user/repo", true},
		{"http://github.com/user/repo", true},
		{"git@github.com:user/repo.git", true},
		{"ssh://git@github.com/user/repo.git", true},
		{"/path/to/local/dir", false},
		{"./relative/path", false},
		{"C:\\Windows\\Path", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsGitURL(tt.path)
			if result != tt.expected {
				t.Errorf("IsGitURL(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestCloneToTemp(t *testing.T) {
	// Test with a public repository
	url := "https://github.com/guttenbergovitz/vigil-cli"

	t.Logf("Cloning %s", url)

	repoDir, cleanup, err := CloneToTemp(url)
	if err != nil {
		t.Fatalf("CloneToTemp failed: %v", err)
	}

	// Verify directory exists
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		cleanup()
		t.Fatalf("Repository directory does not exist: %s", repoDir)
	}

	// Verify .git directory exists
	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		cleanup()
		t.Fatalf(".git directory does not exist: %s", gitDir)
	}

	// Verify lockfile exists (this repo should have one)
	lockFile := filepath.Join(repoDir, "go.mod")
	if _, err := os.Stat(lockFile); os.IsNotExist(err) {
		t.Logf("Warning: go.mod not found, checking for package-lock.json")
		lockFile = filepath.Join(repoDir, "test-project", "package-lock.json")
		if _, err := os.Stat(lockFile); os.IsNotExist(err) {
			cleanup()
			t.Fatalf("Expected lockfile not found in repository")
		}
	}

	t.Logf("Clone successful: %s", repoDir)

	// Cleanup
	cleanup()

	// Verify cleanup worked
	if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
		t.Errorf("Cleanup failed: directory still exists: %s", repoDir)
	}
}
