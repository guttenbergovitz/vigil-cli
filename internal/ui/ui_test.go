package ui

import (
	"testing"
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

// TestModelVulnerabilityFlow verifies vulnerability addition and transition to explorer.
func TestModelVulnerabilityFlow(t *testing.T) {
	m := NewModel()

	// Add test vulnerability
	m.AddVulnerability(VulnEntry{
		Package:        "log4j-core",
		Version:        "2.14.1",
		CVE:            "CVE-2021-44228",
		Severity:       "critical",
		CVSS:           10.0,
		Description:    "Remote code execution in Log4j2 JNDI feature",
		DependencyPath: []string{"my-app", "org.springframework.boot:spring-boot-starter-logging", "org.apache.logging.log4j:log4j-core"},
	})

	if len(m.vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(m.vulns))
	}

	// Mark scan done
	m.SetDone(&ScanResult{
		TotalVulns:    1,
		CriticalVulns: 1,
	})

	if m.state != StateExplorer {
		t.Errorf("expected transition to StateExplorer after SetDone, got %v", m.state)
	}

	if len(m.filteredVulns) != 1 {
		t.Errorf("expected 1 filtered vulnerability in explorer, got %d", len(m.filteredVulns))
	}

	// Test severity filtering
	m.filterSeverity = "high"
	m.applyFilters()
	if len(m.filteredVulns) != 0 {
		t.Errorf("expected 0 vulnerabilities when filtering for High, got %d", len(m.filteredVulns))
	}

	m.filterSeverity = "critical"
	m.applyFilters()
	if len(m.filteredVulns) != 1 {
		t.Errorf("expected 1 vulnerability when filtering for Critical, got %d", len(m.filteredVulns))
	}
}
