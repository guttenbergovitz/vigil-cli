package container

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IssueSeverity represents the risk level of an IaC misconfiguration.
type IssueSeverity string

const (
	High   IssueSeverity = "high"
	Medium IssueSeverity = "medium"
	Low    IssueSeverity = "low"
)

// SecurityIssue represents an audited security rule violation in Dockerfile or CI workflow.
type SecurityIssue struct {
	Source     string        `json:"source"`
	LineNumber int           `json:"line_number"`
	RuleID     string        `json:"rule_id"`
	Title      string        `json:"title"`
	Message    string        `json:"message"`
	Severity   IssueSeverity `json:"severity"`
}

var (
	shaRegex        = regexp.MustCompile(`@[a-f0-9]{40}$`)
	actionTagRegex  = regexp.MustCompile(`uses:\s*([a-zA-Z0-9_\-\./]+)@([a-zA-Z0-9_\-\.]+)`)
)

// AuditDockerfile audits Dockerfile for security misconfigurations.
func AuditDockerfile(path string) ([]SecurityIssue, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Dockerfile: %w", err)
	}
	defer file.Close()

	var issues []SecurityIssue
	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasUserInstruction := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		upperLine := strings.ToUpper(line)

		// Check for USER instruction
		if strings.HasPrefix(upperLine, "USER ") {
			hasUserInstruction = true
		}

		// Rule DOCKER-002: Base image using :latest or unversioned tag
		if strings.HasPrefix(upperLine, "FROM ") {
			image := strings.TrimSpace(line[5:])
			if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, ":") && !strings.Contains(image, "@sha256:")) {
				issues = append(issues, SecurityIssue{
					Source:     path,
					LineNumber: lineNum,
					RuleID:     "DOCKER-002",
					Title:      "Unpinned Docker Base Image Tag",
					Message:    fmt.Sprintf("Base image %q uses :latest or unpinned version tag. Pin to a specific digest or version tag.", image),
					Severity:   Medium,
				})
			}
		}

		// Rule DOCKER-003: Sensitive credentials in ENV instruction
		if strings.HasPrefix(upperLine, "ENV ") {
			if strings.Contains(upperLine, "SECRET") || strings.Contains(upperLine, "PASSWORD") || strings.Contains(upperLine, "TOKEN") || strings.Contains(upperLine, "API_KEY") {
				issues = append(issues, SecurityIssue{
					Source:     path,
					LineNumber: lineNum,
					RuleID:     "DOCKER-003",
					Title:      "Sensitive Data in ENV Instruction",
					Message:    "Avoid declaring secrets in ENV instructions as they persist in the container image metadata.",
					Severity:   High,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Dockerfile: %w", err)
	}

	// Rule DOCKER-001: Missing USER instruction (runs as root)
	if !hasUserInstruction {
		issues = append(issues, SecurityIssue{
			Source:     path,
			LineNumber: 1,
			RuleID:     "DOCKER-001",
			Title:      "Container Running as Root",
			Message:    "No USER instruction found. Containers should specify a non-root USER for runtime execution.",
			Severity:   High,
		})
	}

	return issues, nil
}

// AuditGitHubWorkflow audits GitHub Actions workflow YAML files for security risks.
func AuditGitHubWorkflow(path string) ([]SecurityIssue, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open workflow: %w", err)
	}
	defer file.Close()

	var issues []SecurityIssue
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Rule GHA-002: Insecure pull_request_target trigger
		if strings.Contains(line, "pull_request_target") {
			issues = append(issues, SecurityIssue{
				Source:     path,
				LineNumber: lineNum,
				RuleID:     "GHA-002",
				Title:      "Insecure pull_request_target Trigger",
				Message:    "pull_request_target grants write permissions and secret access to untrusted PRs. Ensure code from PR is not executed directly.",
				Severity:   High,
			})
		}

		// Rule GHA-001: Unpinned GitHub Action (using tag instead of 40-char SHA)
		if matches := actionTagRegex.FindStringSubmatch(line); len(matches) >= 3 {
			actionRef := matches[1] + "@" + matches[2]
			if !shaRegex.MatchString(actionRef) {
				issues = append(issues, SecurityIssue{
					Source:     path,
					LineNumber: lineNum,
					RuleID:     "GHA-001",
					Title:      "Unpinned GitHub Action Tag",
					Message:    fmt.Sprintf("Action %q is pinned to a mutable tag instead of a 40-character commit SHA.", actionRef),
					Severity:   Medium,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}

	return issues, nil
}

// AuditProject audits all Dockerfiles and GitHub Action workflows in a directory.
func AuditProject(dir string) ([]SecurityIssue, error) {
	var allIssues []SecurityIssue

	// 1. Audit Dockerfile if present
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); err == nil {
		issues, err := AuditDockerfile(dockerfilePath)
		if err == nil {
			allIssues = append(allIssues, issues...)
		}
	}

	// 2. Audit .github/workflows directory if present
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if _, err := os.Stat(workflowsDir); err == nil {
		_ = filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
				issues, err := AuditGitHubWorkflow(path)
				if err == nil {
					allIssues = append(allIssues, issues...)
				}
			}
			return nil
		})
	}

	return allIssues, nil
}
