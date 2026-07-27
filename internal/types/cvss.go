package types

import "strings"

// DeriveCVSSFromSeverity derives a CVSS score from severity level as last resort.
func DeriveCVSSFromSeverity(severity Severity) float64 {
	switch strings.ToLower(string(severity)) {
	case "critical":
		return 9.5 // High end of critical range
	case "high":
		return 7.5 // Middle of high range
	case "medium":
		return 5.0 // Middle of medium range
	case "low":
		return 2.5 // Middle of low range
	default:
		return 5.0 // Default to medium if unknown
	}
}

// SeverityFromCVSS maps CVSS score to severity.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Medium
	}
}
