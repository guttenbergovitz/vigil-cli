package license

import (
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestClassifyLicense verifies license classification into Permissive vs Copyleft.
func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		license  string
		expected LicenseCategory
	}{
		{"MIT", Permissive},
		{"Apache-2.0", Permissive},
		{"BSD-3-Clause", Permissive},
		{"ISC", Permissive},
		{"GPL-3.0", Copyleft},
		{"AGPL-3.0-only", Copyleft},
		{"LGPL-2.1", Copyleft},
		{"MPL-2.0", Copyleft},
		{"CustomNonStandard", Unknown},
	}

	for _, tt := range tests {
		got := ClassifyLicense(tt.license)
		if got != tt.expected {
			t.Errorf("ClassifyLicense(%q) = %s; want %s", tt.license, got, tt.expected)
		}
	}
}

// TestAnalyzeGraphLicenses verifies license scanning over a DependencyGraph.
func TestAnalyzeGraphLicenses(t *testing.T) {
	graph := types.NewDependencyGraph()
	node1 := graph.AddNode("express", "4.18.2", types.Production, true)
	node1.Vulnerabilities = nil // test node
	node2 := graph.AddNode("gpl-lib", "1.0.0", types.Production, false)
	_ = node2

	// Mock license metadata map
	licensesMap := map[string]string{
		"express@4.18.2": "MIT",
		"gpl-lib@1.0.0":  "GPL-3.0",
	}

	findings := AnalyzeGraphLicenses(graph, licensesMap)
	if len(findings) != 2 {
		t.Fatalf("expected 2 license findings, got %d", len(findings))
	}

	hasCopyleft := false
	for _, f := range findings {
		if f.Category == Copyleft {
			hasCopyleft = true
			if f.PackageName != "gpl-lib" {
				t.Errorf("expected gpl-lib to be copyleft, got %s", f.PackageName)
			}
		}
	}

	if !hasCopyleft {
		t.Errorf("expected copyleft finding for gpl-lib")
	}
}
