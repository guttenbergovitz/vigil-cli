package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestText(t *testing.T) {
	// Setup sample data
	scannedAt := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	result := &types.ScanResult{
		ProjectPath:   "/tmp/test",
		ScannedAt:     scannedAt,
		LockFile:      "package-lock.json",
		Dependencies:  []types.Dependency{{Name: "test-dep", Version: "1.0.0"}},
		TotalVulns:    1,
		CriticalVulns: 1,
		HighVulns:     0,
		MediumVulns:   0,
		LowVulns:      0,
	}

	// Add a vulnerability
	result.Dependencies[0].Vulnerabilities = []types.Vulnerability{
		{
			ID:          "CVE-2023-1234",
			Severity:    types.Critical,
			Summary:     "Test Vulnerability",
			Description: "This is a test vulnerability description that is quite long and should be truncated if it exceeds the limit.",
		},
	}

	var buf bytes.Buffer
	err := Text(result, &buf)
	if err != nil {
		t.Fatalf("Text() error = %v", err)
	}

	output := buf.String()

	// Verify output contains key elements
	expectedStrings := []string{
		"Project: /tmp/test",
		"Lock file: package-lock.json",
		"CRITICAL (1)",
		"test-dep@1.0.0",
		"CVE: CVE-2023-1234",
		"Summary: Test Vulnerability",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(output, s) {
			t.Errorf("Text() output missing %q", s)
		}
	}
}

func TestTruncateText(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactlength", 11, "exactlength"},
		{"toolongtext", 5, "toolo…"},
	}

	for _, tt := range tests {
		got := truncateText(tt.input, tt.maxLen)
		if got != tt.expected {
			t.Errorf("truncateText(%q, %d) = %q; want %q", tt.input, tt.maxLen, got, tt.expected)
		}
	}
}
