package report

import (
	"fmt"
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
	"time"
)

// Text generates a text report with supply chain context
func Text(result *models.ScanResult, out io.Writer) error {
	fmt.Fprintf(out, "Project: %s\n", result.ProjectPath)
	fmt.Fprintf(out, "Scanned: %s\n", result.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "Lock file: %s\n", result.LockFile)
	fmt.Fprintf(out, "Dependencies scanned: %d\n\n", len(result.Dependencies))

	if result.TotalVulns == 0 {
		fmt.Fprintf(out, "✓ No vulnerabilities found\n")
		return nil
	}

	// Summary
	fmt.Fprintf(out, "Vulnerabilities Summary:\n")
	if result.CriticalVulns > 0 {
		fmt.Fprintf(out, "  🔴 Critical: %d\n", result.CriticalVulns)
	}
	if result.HighVulns > 0 {
		fmt.Fprintf(out, "  🟠 High: %d\n", result.HighVulns)
	}
	if result.MediumVulns > 0 {
		fmt.Fprintf(out, "  🟡 Medium: %d\n", result.MediumVulns)
	}
	if result.LowVulns > 0 {
		fmt.Fprintf(out, "  🔵 Low: %d\n", result.LowVulns)
	}
	fmt.Fprintf(out, "\n")

	// Group by severity with supply chain context
	if result.CriticalVulns > 0 {
		fmt.Fprintf(out, "CRITICAL (%d)\n", result.CriticalVulns)
		for _, dep := range result.Dependencies {
			for _, vuln := range dep.Vulnerabilities {
				if vuln.Severity == models.Critical {
					depType := "production"
					if dep.Type == models.Development {
						depType = "dev"
					}
					fmt.Fprintf(out, "├── %s@%s (%s)\n", dep.Name, dep.Version, depType)
					fmt.Fprintf(out, "│   ├── CVE: %s\n", vuln.ID)
					if vuln.CVSSScore > 0 {
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0", vuln.CVSSScore)
						if vuln.CVSSVector != "" {
							fmt.Fprintf(out, " %s", vuln.CVSSVector)
						}
						fmt.Fprintf(out, "\n")
					}
					fmt.Fprintf(out, "│   ├── Summary: %s\n", vuln.Summary)
					if vuln.Description != "" && vuln.Description != vuln.Summary {
						fmt.Fprintf(out, "│   ├── Description: %s\n", truncateText(vuln.Description, 100))
					}
					if len(vuln.References) > 0 {
						fmt.Fprintf(out, "│   ├── References:\n")
						for i, ref := range vuln.References {
							if i < 3 { // Show first 3 references
								fmt.Fprintf(out, "│   │   └── %s\n", ref)
							}
						}
					}
					if vuln.RiskScore > 0 {
						fmt.Fprintf(out, "│   └── Risk Score: %d/100\n", vuln.RiskScore)
					}
				}
			}
		}
		fmt.Fprintf(out, "\n")
	}

	if result.HighVulns > 0 {
		fmt.Fprintf(out, "HIGH (%d)\n", result.HighVulns)
		for _, dep := range result.Dependencies {
			for _, vuln := range dep.Vulnerabilities {
				if vuln.Severity == models.High {
					depType := "production"
					if dep.Type == models.Development {
						depType = "dev"
					}
					fmt.Fprintf(out, "├── %s@%s (%s)\n", dep.Name, dep.Version, depType)
					fmt.Fprintf(out, "│   ├── CVE: %s\n", vuln.ID)
					if vuln.CVSSScore > 0 {
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0", vuln.CVSSScore)
						if vuln.CVSSVector != "" {
							fmt.Fprintf(out, " %s", vuln.CVSSVector)
						}
						fmt.Fprintf(out, "\n")
					}
					fmt.Fprintf(out, "│   ├── Summary: %s\n", vuln.Summary)
					if vuln.Description != "" && vuln.Description != vuln.Summary {
						fmt.Fprintf(out, "│   ├── Description: %s\n", truncateText(vuln.Description, 100))
					}
					if vuln.RiskScore > 0 {
						fmt.Fprintf(out, "│   └── Risk Score: %d/100\n", vuln.RiskScore)
					}
				}
			}
		}
		fmt.Fprintf(out, "\n")
	}

	if result.MediumVulns > 0 {
		fmt.Fprintf(out, "MEDIUM (%d)\n", result.MediumVulns)
		for _, dep := range result.Dependencies {
			for _, vuln := range dep.Vulnerabilities {
				if vuln.Severity == models.Medium {
					depType := "production"
					if dep.Type == models.Development {
						depType = "dev"
					}
					fmt.Fprintf(out, "├── %s@%s (%s)\n", dep.Name, dep.Version, depType)
					fmt.Fprintf(out, "│   ├── CVE: %s\n", vuln.ID)
					if vuln.CVSSScore > 0 {
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0", vuln.CVSSScore)
						if vuln.CVSSVector != "" {
							fmt.Fprintf(out, " %s", vuln.CVSSVector)
						}
						fmt.Fprintf(out, "\n")
					}
					fmt.Fprintf(out, "│   ├── Summary: %s\n", vuln.Summary)
					if vuln.Description != "" && vuln.Description != vuln.Summary {
						fmt.Fprintf(out, "│   └── Description: %s\n", truncateText(vuln.Description, 100))
					}
				}
			}
		}
		fmt.Fprintf(out, "\n")
	}

	if result.LowVulns > 0 {
		fmt.Fprintf(out, "LOW (%d)\n", result.LowVulns)
		for _, dep := range result.Dependencies {
			for _, vuln := range dep.Vulnerabilities {
				if vuln.Severity == models.Low {
					depType := "production"
					if dep.Type == models.Development {
						depType = "dev"
					}
					fmt.Fprintf(out, "├── %s@%s (%s)\n", dep.Name, dep.Version, depType)
					fmt.Fprintf(out, "│   ├── CVE: %s\n", vuln.ID)
					if vuln.CVSSScore > 0 {
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0", vuln.CVSSScore)
						if vuln.CVSSVector != "" {
							fmt.Fprintf(out, " %s", vuln.CVSSVector)
						}
						fmt.Fprintf(out, "\n")
					}
					fmt.Fprintf(out, "│   └── Summary: %s\n", vuln.Summary)
				}
			}
		}
		fmt.Fprintf(out, "\n")
	}

	fmt.Fprintf(out, "Note: Vulnerabilities in 'dev' dependencies are lower priority as they don't affect production.\n")
	fmt.Fprintf(out, "Risk Score considers both severity and production context (0-100).\n")

	return nil
}

// truncateText limits text length and adds ellipsis if needed
func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "…"
}
