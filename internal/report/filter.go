package report

import "github.com/guttenbergovitz/vigil-cli/pkg/models"

// FilterByLevel filters scan results to show only vulns at or above specified level
func FilterByLevel(result *models.ScanResult, level string) *models.ScanResult {
	severityMap := map[string]models.Severity{
		"low":      models.Low,
		"medium":   models.Medium,
		"high":     models.High,
		"critical": models.Critical,
	}

	minSev, ok := severityMap[level]
	if !ok {
		return result
	}

	severityOrder := map[models.Severity]int{
		models.Low:      1,
		models.Medium:   2,
		models.High:     3,
		models.Critical: 4,
	}

	filtered := &models.ScanResult{
		Version:       result.Version,
		ProjectPath:   result.ProjectPath,
		ScannedAt:     result.ScannedAt,
		LockFile:      result.LockFile,
		LockFileHash:  result.LockFileHash,
		Dependencies:  make([]models.Dependency, 0),
		TotalVulns:    0,
		CriticalVulns: 0,
		HighVulns:     0,
		MediumVulns:   0,
		LowVulns:      0,
	}

	for _, dep := range result.Dependencies {
		var filteredVulns []models.Vulnerability
		for _, vuln := range dep.Vulnerabilities {
			if severityOrder[vuln.Severity] >= severityOrder[minSev] {
				filteredVulns = append(filteredVulns, vuln)
			}
		}

		if len(filteredVulns) > 0 {
			dep.Vulnerabilities = filteredVulns
			filtered.Dependencies = append(filtered.Dependencies, dep)

			// Recount vulnerabilities
			for _, vuln := range filteredVulns {
				filtered.TotalVulns++
				switch vuln.Severity {
				case models.Critical:
					filtered.CriticalVulns++
				case models.High:
					filtered.HighVulns++
				case models.Medium:
					filtered.MediumVulns++
				case models.Low:
					filtered.LowVulns++
				}
			}
		}
	}

	return filtered
}
