package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsGitURL checks if the path is a git repository URL.
func IsGitURL(path string) bool {
	return strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "http://") ||
		strings.HasPrefix(path, "git@") ||
		strings.HasPrefix(path, "ssh://")
}

// CloneToTemp clones a git repository to a temporary directory.
// Returns the temporary directory path and cleanup function.
func CloneToTemp(url string) (string, func(), error) {
	// Create temp dir
	tmpDir, err := os.MkdirTemp("", "vigil-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// Clone repository
	repoDir := filepath.Join(tmpDir, "repo")

	cmd := exec.Command("git", "clone", "--depth", "1", url, repoDir)

	// Use GITHUB_TOKEN if available for https:// URLs
	if strings.HasPrefix(url, "https://") {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			// Inject token into URL for GitHub
			if strings.Contains(url, "github.com") {
				// Transform https://github.com/user/repo to https://token@github.com/user/repo
				url = strings.Replace(url, "https://", fmt.Sprintf("https://%s@", token), 1)
				cmd = exec.Command("git", "clone", "--depth", "1", url, repoDir)
			}
		}
	}

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone failed: %w\nOutput: %s", err, string(output))
	}

	return repoDir, cleanup, nil
}
