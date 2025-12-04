package export

import (
	"fmt"
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// Markdown exports scan results in Markdown format.
func Markdown(result *models.ScanResult, w io.Writer) error {
	fmt.Fprintf(w, "# Vulnerability Report\n\n")
	fmt.Fprintf(w, "**Project:** %s\n", result.ProjectPath)
	fmt.Fprintf(w, "**Scanned:** %s\n", result.ScannedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "**Lock file:** %s\n\n", result.LockFile)

	// Summary section
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	fmt.Fprintf(w, "| Critical | %d |\n", result.CriticalVulns)
	fmt.Fprintf(w, "| High     | %d |\n", result.HighVulns)
	fmt.Fprintf(w, "| Medium   | %d |\n", result.MediumVulns)
	fmt.Fprintf(w, "| Low      | %d |\n\n", result.LowVulns)

	// Vulnerabilities by severity
	severities := []models.Severity{models.Critical, models.High, models.Medium, models.Low}

	for _, severity := range severities {
		var vulns []models.Vulnerability
		for _, dep := range result.Dependencies {
			for _, v := range dep.Vulnerabilities {
				if v.Severity == severity {
					vulns = append(vulns, v)
				}
			}
		}

		if len(vulns) == 0 {
			continue
		}

		fmt.Fprintf(w, "## %s Severity (%d)\n\n", severity, len(vulns))

		for i, vuln := range vulns {
			// Find package
			var depName, depVersion string
			for _, dep := range result.Dependencies {
				for _, v := range dep.Vulnerabilities {
					if v.ID == vuln.ID {
						depName = dep.Name
						depVersion = dep.Version
						break
					}
				}
			}

			fmt.Fprintf(w, "### %d. %s\n\n", i+1, vuln.ID)
			fmt.Fprintf(w, "- **Package:** %s@%s\n", depName, depVersion)
			fmt.Fprintf(w, "- **Severity:** %s\n", vuln.Severity)
			fmt.Fprintf(w, "- **Risk Score:** %d/100\n", vuln.RiskScore)
			fmt.Fprintf(w, "- **Summary:** %s\n", vuln.Summary)

			if len(vuln.References) > 0 {
				fmt.Fprintf(w, "- **References:**\n")
				for _, ref := range vuln.References {
					fmt.Fprintf(w, "  - %s\n", ref)
				}
			}
			fmt.Fprintf(w, "\n")
		}
	}

	return nil
}
