package export

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// CSV exports scan results in CSV format.
func CSV(result *models.ScanResult, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"package", "version", "type", "cve_id", "summary", "severity", "risk_score"}); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	// Write data rows
	for _, dep := range result.Dependencies {
		if len(dep.Vulnerabilities) == 0 {
			// Write row for dependency with no vulns
			if err := writer.Write([]string{
				dep.Name,
				dep.Version,
				string(dep.Type),
				"",
				"",
				"",
				"",
			}); err != nil {
				return fmt.Errorf("write CSV row: %w", err)
			}
		} else {
			// Write row for each vulnerability
			for _, vuln := range dep.Vulnerabilities {
				if err := writer.Write([]string{
					dep.Name,
					dep.Version,
					string(dep.Type),
					vuln.ID,
					vuln.Summary,
					string(vuln.Severity),
					fmt.Sprintf("%d", vuln.RiskScore),
				}); err != nil {
					return fmt.Errorf("write CSV row: %w", err)
				}
			}
		}
	}

	return nil
}
