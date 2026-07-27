package report

import "github.com/guttenbergovitz/vigil-cli/internal/types"

// FilterByLevel filters scan results to show only vulns at or above specified level
func FilterByLevel(result *types.ScanResult, level string) *types.ScanResult {
	minSev, ok := types.SeverityMap[level]
	if !ok {
		return result
	}

	filtered := &types.ScanResult{
		Version:       result.Version,
		ProjectPath:   result.ProjectPath,
		ScannedAt:     result.ScannedAt,
		LockFile:      result.LockFile,
		LockFileHash:  result.LockFileHash,
		Dependencies:  make([]types.Dependency, 0),
		TotalVulns:    0,
		CriticalVulns: 0,
		HighVulns:     0,
		MediumVulns:   0,
		LowVulns:      0,
	}

	for _, dep := range result.Dependencies {
		var filteredVulns []types.Vulnerability
		for _, vuln := range dep.Vulnerabilities {
			if vuln.Severity.HigherOrEqualThan(minSev) {
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
				case types.Critical:
					filtered.CriticalVulns++
				case types.High:
					filtered.HighVulns++
				case types.Medium:
					filtered.MediumVulns++
				case types.Low:
					filtered.LowVulns++
				}
			}
		}
	}

	return filtered
}
