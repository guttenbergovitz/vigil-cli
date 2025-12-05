package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Table generates a compact tabular report similar to Trivy
func Table(result *types.ScanResult, out io.Writer) error {
	if result.TotalVulns == 0 {
		fmt.Fprintf(out, "✓ No vulnerabilities found\n")
		return nil
	}

	// Process vulnerabilities
	entries := processVulnerabilities(result)

	// Group by severity for colored output
	bySeverity := groupBySeverity(entries)

	// Determine release gate
	gate, gateReasons := determineReleaseGate(result, entries)

	// Print header
	fmt.Fprintf(out, "\n")
	writeTableHeader(out)

	// Print vulnerabilities in severity order
	severityOrder := []types.Severity{types.Critical, types.High, types.Medium, types.Low}
	first := true

	for _, severity := range severityOrder {
		vulns, ok := bySeverity[severity]
		if !ok || len(vulns) == 0 {
			continue
		}

		if !first {
			fmt.Fprintf(out, "\n")
		}
		first = false

		for _, entry := range vulns {
			writeTableRow(out, entry)
		}
	}

	fmt.Fprintf(out, "\n")
	writeTableSummary(out, result, entries, gate, gateReasons)

	return nil
}

func writeTableHeader(out io.Writer) {
	fmt.Fprintf(out, "%-25s │ %-20s │ %-10s │ %-15s │ %-15s │ %-12s │ %s\n",
		"Library", "Vuln ID", "Severity", "Exploit Type", "Exploitability", "Fix Available", "Recommended Action")
	fmt.Fprintf(out, "%s┼%s┼%s┼%s┼%s┼%s┼%s\n",
		strings.Repeat("─", 26),
		strings.Repeat("─", 22),
		strings.Repeat("─", 12),
		strings.Repeat("─", 17),
		strings.Repeat("─", 17),
		strings.Repeat("─", 14),
		strings.Repeat("─", 30))
}

func writeTableRow(out io.Writer, entry VulnEntry) {
	// Truncate long values
	library := truncate(entry.Library+"@"+entry.Version, 24)
	vulnID := truncate(entry.VulnID, 19)
	severity := colorSeverity(entry.Severity)
	exploitType := truncate(string(entry.ExploitType), 14)
	exploitability := truncate(string(entry.Exploitability), 14)
	fixStatus := truncate(entry.FixStatus, 11)
	action := truncate(string(entry.RecommendedAction), 28)

	// Add environment indicator for dev deps
	if entry.Environment == "dev" {
		library = library + " (dev)"
	}

	fmt.Fprintf(out, "%-25s │ %-20s │ %-10s │ %-15s │ %-15s │ %-12s │ %s\n",
		library, vulnID, severity, exploitType, exploitability, fixStatus, action)
}

func writeTableSummary(out io.Writer, result *types.ScanResult, entries []VulnEntry, gate ReleaseGate, reasons []string) {
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "SUMMARY\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n\n")

	// Total findings
	fmt.Fprintf(out, "Total Findings: %d", result.TotalVulns)
	if result.CriticalVulns > 0 {
		fmt.Fprintf(out, "  │  🔴 CRITICAL: %d", result.CriticalVulns)
	}
	if result.HighVulns > 0 {
		fmt.Fprintf(out, "  │  🟠 HIGH: %d", result.HighVulns)
	}
	if result.MediumVulns > 0 {
		fmt.Fprintf(out, "  │  🟡 MEDIUM: %d", result.MediumVulns)
	}
	if result.LowVulns > 0 {
		fmt.Fprintf(out, "  │  🔵 LOW: %d", result.LowVulns)
	}
	fmt.Fprintf(out, "\n\n")

	// Production exploitable count
	prodExploitable := 0
	for _, entry := range entries {
		if entry.Environment == "production" && entry.Exploitability == ExploitableYes {
			prodExploitable++
		}
	}

	if prodExploitable > 0 {
		fmt.Fprintf(out, "⚠️  Production-Exploitable: %d findings require immediate attention\n", prodExploitable)
	}

	// Release gate
	fmt.Fprintf(out, "\n%s\n", gate)
	if len(reasons) > 0 {
		for _, reason := range reasons {
			fmt.Fprintf(out, "  • %s\n", reason)
		}
	}

	fmt.Fprintf(out, "\n")
}

func colorSeverity(severity types.Severity) string {
	switch severity {
	case types.Critical:
		return "CRITICAL"
	case types.High:
		return "HIGH"
	case types.Medium:
		return "MEDIUM"
	case types.Low:
		return "LOW"
	default:
		return strings.ToUpper(string(severity))
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-1] + "…"
}
