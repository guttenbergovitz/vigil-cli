package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestModelInitialState verifies initial TUI model state.
func TestModelInitialState(t *testing.T) {
	m := NewModel()
	if m.state != StateScanning {
		t.Errorf("expected initial state StateScanning, got %v", m.state)
	}

	if m.progress.Completed {
		t.Errorf("expected initial progress completed false")
	}
}

// TestModelLazygitMultiPaneDashboard verifies panes, word-wrapping, tabs, secrets, IaC, licenses, reason flagged, and grouping.
func TestModelLazygitMultiPaneDashboard(t *testing.T) {
	m := NewModel()

	// Add test vulnerability
	m.AddVulnerability(VulnEntry{
		Package:        "log4j-core",
		Version:        "2.14.1",
		CVE:            "CVE-2021-44228",
		Severity:       "critical",
		CVSS:           10.0,
		Description:    "Remote code execution in Log4j2 JNDI feature affects certain React Server Components packages for versions 19.0.x",
		CVEDescription: "A vulnerability affects certain React Server Components packages for versions 19.0.x. A specially crafted HTTP request can be sent to any App Router Server Function endpoint.",
		DependencyPath: []string{"my-app", "spring-boot-starter-logging", "log4j-core"},
	})

	secList := []secrets.SecretFinding{
		{
			FilePath:    "config.env",
			LineNumber:  2,
			LineContent: "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
			Type:        secrets.AWSKey,
			Match:       "AKIAIOSFODNN7EXAMPLE",
			Entropy:     4.8,
		},
	}

	iacList := []container.SecurityIssue{
		{
			Source:     "Dockerfile",
			LineNumber: 1,
			RuleID:     "DOCKER-001",
			Title:      "Container Running as Root",
			Message:    "No USER instruction found",
			Severity:   container.High,
		},
	}

	licList := []license.LicenseFinding{
		{
			PackageName: "gpl-lib",
			Version:     "1.0.0",
			License:     "GPL-3.0",
			Category:    license.Copyleft,
		},
	}

	// Mark scan done with graph and full spectrum findings
	m.SetDone(&types.ScanResult{
		TotalVulns:    1,
		CriticalVulns: 1,
	}, nil, secList, iacList, licList)

	if m.state != StateExplorer {
		t.Errorf("expected transition to StateExplorer after SetDone, got %v", m.state)
	}

	// Test Tab 1: Vulnerabilities
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabVulnerabilities, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].ReasonFlagged == "" {
		t.Errorf("expected non-empty ReasonFlagged for SCA vulnerability")
	}

	// Test Lazygit Pane Focus Cycle (Tab)
	if m.activePane != PaneTable {
		t.Errorf("expected default active pane PaneTable, got %v", m.activePane)
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyTab})
	if m.activePane != PaneReason {
		t.Errorf("expected active pane PaneReason after Tab, got %v", m.activePane)
	}

	// Test Window Maximization (w)
	if m.isMaximized {
		t.Errorf("expected default isMaximized false")
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if !m.isMaximized {
		t.Errorf("expected isMaximized true after pressing 'w'")
	}
	m.handleKeyPress(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if m.isMaximized {
		t.Errorf("expected isMaximized false after pressing 'w' again")
	}

	// Test Tab 2: Secrets
	m.activeTab = TabSecrets
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabSecrets, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].Domain != "SECRET" {
		t.Errorf("expected domain SECRET, got %s", m.filteredItems[0].Domain)
	}

	// Test Tab 3: IaC
	m.activeTab = TabIaC
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabIaC, got %d", len(m.filteredItems))
	}
	if m.filteredItems[0].ID != "DOCKER-001" {
		t.Errorf("expected rule ID DOCKER-001, got %s", m.filteredItems[0].ID)
	}

	// Test Tab 4: Licenses
	m.activeTab = TabLicenses
	m.applyFilters()
	if len(m.filteredItems) != 1 {
		t.Fatalf("expected 1 item in TabLicenses, got %d", len(m.filteredItems))
	}

	// Test Grouping Mode
	m.activeTab = TabVulnerabilities
	m.groupMode = GroupSeverity
	m.applyFilters()
	if len(m.filteredItems) < 2 {
		t.Errorf("expected grouped items including header, got %d", len(m.filteredItems))
	}
}
