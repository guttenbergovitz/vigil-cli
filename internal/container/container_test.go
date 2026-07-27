package container

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAuditDockerfile verifies Dockerfile security rules.
func TestAuditDockerfile(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")

	content := `FROM node:latest
WORKDIR /app
COPY . .
ENV SECRET_KEY=12345
RUN npm install
CMD ["node", "index.js"]
`
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	issues, err := AuditDockerfile(dockerfilePath)
	if err != nil {
		t.Fatalf("AuditDockerfile returned error: %v", err)
	}

	if len(issues) < 2 {
		t.Fatalf("expected at least 2 security issues in sample Dockerfile, got %d", len(issues))
	}

	hasLatestTag := false
	hasMissingUser := false

	for _, issue := range issues {
		if issue.RuleID == "DOCKER-001" { // Missing USER
			hasMissingUser = true
		}
		if issue.RuleID == "DOCKER-002" { // Using :latest tag
			hasLatestTag = true
		}
	}

	if !hasMissingUser {
		t.Errorf("expected DOCKER-001 rule violation (missing USER)")
	}
	if !hasLatestTag {
		t.Errorf("expected DOCKER-002 rule violation (using :latest tag)")
	}
}

// TestAuditGitHubWorkflow verifies GitHub Actions workflow security rules.
func TestAuditGitHubWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "ci.yml")

	content := `name: CI
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm test
`
	if err := os.WriteFile(workflowPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write ci.yml: %v", err)
	}

	issues, err := AuditGitHubWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("AuditGitHubWorkflow returned error: %v", err)
	}

	if len(issues) < 2 {
		t.Fatalf("expected at least 2 workflow issues, got %d", len(issues))
	}

	hasPRTarget := false
	hasUnpinnedAction := false

	for _, issue := range issues {
		if issue.RuleID == "GHA-001" { // Unpinned action tag instead of SHA
			hasUnpinnedAction = true
		}
		if issue.RuleID == "GHA-002" { // Dangerous pull_request_target trigger
			hasPRTarget = true
		}
	}

	if !hasUnpinnedAction {
		t.Errorf("expected GHA-001 rule violation (unpinned action tag)")
	}
	if !hasPRTarget {
		t.Errorf("expected GHA-002 rule violation (pull_request_target trigger)")
	}
}
