package export

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func TestCSVExport(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		ProjectPath: "/test",
		ScannedAt:   now,
		LockFile:    "package-lock.json",
		Dependencies: []types.Dependency{
			{
				Name:    "express",
				Version: "4.18.0",
				Type:    types.Production,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:       "CVE-2024-1234",
						Summary:  "XSS vulnerability",
						Severity: types.Medium,
						RiskScore: 45,
					},
				},
			},
			{
				Name:            "lodash",
				Version:         "4.17.21",
				Type:            types.Production,
				Vulnerabilities: []types.Vulnerability{},
			},
		},
		CriticalVulns: 0,
		HighVulns:     0,
		MediumVulns:   1,
		LowVulns:      0,
	}

	var buf bytes.Buffer
	err := CSV(result, &buf)
	if err != nil {
		t.Fatalf("CSV() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "express") || !strings.Contains(output, "CVE-2024-1234") {
		t.Errorf("CSV output missing expected content:\n%s", output)
	}
	if !strings.Contains(output, "package,version") {
		t.Errorf("CSV header missing")
	}
}

func TestMarkdownExport(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		ProjectPath: "/test",
		ScannedAt:   now,
		LockFile:    "package-lock.json",
		Dependencies: []types.Dependency{
			{
				Name:    "express",
				Version: "4.18.0",
				Type:    types.Production,
				Vulnerabilities: []types.Vulnerability{
					{
						ID:       "CVE-2024-1234",
						Summary:  "XSS vulnerability",
						Severity: types.Critical,
						RiskScore: 95,
					},
				},
			},
		},
		CriticalVulns: 1,
	}

	var buf bytes.Buffer
	err := Markdown(result, &buf)
	if err != nil {
		t.Fatalf("Markdown() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "# Vulnerability Report") {
		t.Errorf("Markdown missing header")
	}
	if !strings.Contains(output, "Critical") || !strings.Contains(output, "CVE-2024-1234") {
		t.Errorf("Markdown missing vulnerability details")
	}
}

func TestJSONExport(t *testing.T) {
	now := time.Now()
	result := &types.ScanResult{
		ProjectPath: "/test",
		ScannedAt:   now,
		LockFile:    "package-lock.json",
		Dependencies: []types.Dependency{
			{
				Name:            "express",
				Version:         "4.18.0",
				Type:            types.Production,
				Vulnerabilities: []types.Vulnerability{},
			},
		},
	}

	var buf bytes.Buffer
	err := JSON(result, &buf)
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "express") || !strings.Contains(output, "4.18.0") {
		t.Errorf("JSON output missing expected content")
	}
}
