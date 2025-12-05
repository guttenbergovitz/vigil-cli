package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ReleaseGate represents the release decision
type ReleaseGate string

const (
	ReleaseProceed             ReleaseGate = "✅ Release can proceed"
	ReleaseAllowWithMitigation ReleaseGate = "⚠️  Release allowed with mitigations"
	ReleaseBlock               ReleaseGate = "❌ Release must be blocked until fixes are applied"
)

// VulnEntry represents a processed vulnerability entry for the report
type VulnEntry struct {
	Library             string
	Version             string
	Environment         string
	VulnID              string
	Severity            types.Severity
	CVSS                float64
	CVSSVector          string
	ExploitType         ExploitType
	Exploitability      RuntimeExploitability
	DependencyPath      string
	TechnicalSummary    string
	FixStatus           string
	RecommendedAction   RecommendedAction
	OperationalRiskNote string
}

// Security generates a production-ready security report
func Security(result *types.ScanResult, out io.Writer) error {
	// Process all vulnerabilities
	entries := processVulnerabilities(result)

	// Group by severity
	bySeverity := groupBySeverity(entries)

	// Analyze systemic risks
	riskSignals := analyzeSystemicRisks(result)

	// Determine release gate
	gate, gateReason := determineReleaseGate(result, entries)

	// Generate report
	writeHeader(out, result)
	writeExecutiveSummary(out, result, entries)
	writeVulnerabilityDetails(out, bySeverity)
	writeSystemicRiskSignals(out, riskSignals)
	writeReleaseGateRecommendation(out, gate, gateReason)

	return nil
}

func writeHeader(out io.Writer, result *types.ScanResult) {
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "                        SECURITY VULNERABILITY REPORT                           \n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n\n")
	fmt.Fprintf(out, "Project:      %s\n", result.ProjectPath)
	fmt.Fprintf(out, "Scan Date:    %s\n", result.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "Lock File:    %s\n", result.LockFile)
	fmt.Fprintf(out, "Dependencies: %d\n\n", len(result.Dependencies))
}

func writeExecutiveSummary(out io.Writer, result *types.ScanResult, entries []VulnEntry) {
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "1. EXECUTIVE RISK SUMMARY\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n\n")

	// Total findings by severity
	fmt.Fprintf(out, "Total Findings by Severity:\n")
	if result.CriticalVulns > 0 {
		fmt.Fprintf(out, "  CRITICAL: %d\n", result.CriticalVulns)
	}
	if result.HighVulns > 0 {
		fmt.Fprintf(out, "  HIGH:     %d\n", result.HighVulns)
	}
	if result.MediumVulns > 0 {
		fmt.Fprintf(out, "  MEDIUM:   %d\n", result.MediumVulns)
	}
	if result.LowVulns > 0 {
		fmt.Fprintf(out, "  LOW:      %d\n", result.LowVulns)
	}
	fmt.Fprintf(out, "\n")

	// Count production-exploitable
	prodExploitable := 0
	devOnly := 0
	for _, entry := range entries {
		if entry.Environment == "production" && entry.Exploitability == ExploitableYes {
			prodExploitable++
		}
		if entry.Environment == "dev" || entry.Environment == "test" {
			devOnly++
		}
	}

	fmt.Fprintf(out, "Production-Exploitable Findings: %d\n", prodExploitable)
	fmt.Fprintf(out, "Dev/Test-Only Findings:          %d\n", devOnly)
	fmt.Fprintf(out, "\n")

	// Immediate release blockers
	hasBlockers := result.CriticalVulns > 0
	if hasBlockers {
		fmt.Fprintf(out, "Immediate Release Blockers: YES\n")
		fmt.Fprintf(out, "  - %d CRITICAL vulnerabilities require immediate attention\n", result.CriticalVulns)
	} else {
		fmt.Fprintf(out, "Immediate Release Blockers: NO\n")
	}
	fmt.Fprintf(out, "\n")
}

func writeVulnerabilityDetails(out io.Writer, bySeverity map[types.Severity][]VulnEntry) {
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "2. VULNERABILITIES GROUPED BY SEVERITY\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n\n")

	// Process in order: CRITICAL, HIGH, MEDIUM, LOW
	severityOrder := []types.Severity{types.Critical, types.High, types.Medium, types.Low}

	for _, severity := range severityOrder {
		entries, ok := bySeverity[severity]
		if !ok || len(entries) == 0 {
			continue
		}

		fmt.Fprintf(out, "───────────────────────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(out, "%s (%d)\n", strings.ToUpper(string(severity)), len(entries))
		fmt.Fprintf(out, "───────────────────────────────────────────────────────────────────────────────\n\n")

		for i, entry := range entries {
			fmt.Fprintf(out, "[%d] %s@%s\n", i+1, entry.Library, entry.Version)
			fmt.Fprintf(out, "\n")
			fmt.Fprintf(out, "Environment:           %s\n", entry.Environment)
			fmt.Fprintf(out, "Vulnerability ID:      %s\n", entry.VulnID)
			fmt.Fprintf(out, "Severity:              %s\n", strings.ToUpper(string(entry.Severity)))
			if entry.CVSS > 0 {
				fmt.Fprintf(out, "CVSS:                  %.1f/10.0", entry.CVSS)
				if entry.CVSSVector != "" {
					fmt.Fprintf(out, " (%s)", entry.CVSSVector)
				}
				fmt.Fprintf(out, "\n")
			}
			fmt.Fprintf(out, "Exploit Type:          %s\n", entry.ExploitType)
			fmt.Fprintf(out, "Runtime Exploitability: %s\n", entry.Exploitability)
			if entry.DependencyPath != "" {
				fmt.Fprintf(out, "Dependency Path:       %s\n", entry.DependencyPath)
			}
			fmt.Fprintf(out, "\n")
			fmt.Fprintf(out, "Technical Summary:\n")
			fmt.Fprintf(out, "  %s\n", wrapText(entry.TechnicalSummary, 78))
			fmt.Fprintf(out, "\n")
			fmt.Fprintf(out, "Fix Status:            %s\n", entry.FixStatus)
			fmt.Fprintf(out, "Recommended Action:    %s\n", entry.RecommendedAction)
			fmt.Fprintf(out, "\n")
			fmt.Fprintf(out, "Operational Risk Note:\n")
			fmt.Fprintf(out, "  %s\n", wrapText(entry.OperationalRiskNote, 78))
			fmt.Fprintf(out, "\n")

			if i < len(entries)-1 {
				fmt.Fprintf(out, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n")
			}
		}

		fmt.Fprintf(out, "\n")
	}
}

func writeSystemicRiskSignals(out io.Writer, signals map[string]interface{}) {
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "3. SYSTEMIC RISK INDICATORS\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n\n")

	if len(signals) == 0 {
		fmt.Fprintf(out, "No systemic risk patterns detected.\n\n")
		return
	}

	// Repeated vulnerable packages
	if repeatedPkgs, ok := signals["repeated_packages"].([]string); ok && len(repeatedPkgs) > 0 {
		fmt.Fprintf(out, "Repeated Vulnerable Package Families:\n")
		for _, pkg := range repeatedPkgs {
			fmt.Fprintf(out, "  - %s\n", pkg)
		}
		fmt.Fprintf(out, "\n")
	}

	// Hot dependency clusters
	if hotClusters, ok := signals["hot_clusters"].([]string); ok && len(hotClusters) > 0 {
		fmt.Fprintf(out, "Hot Dependency Clusters (multiple findings):\n")
		for _, cluster := range hotClusters {
			fmt.Fprintf(out, "  - %s\n", cluster)
		}
		fmt.Fprintf(out, "\n")
	}

	// Critical layer impacts
	if criticalLayers, ok := signals["critical_layers"].([]string); ok && len(criticalLayers) > 0 {
		fmt.Fprintf(out, "CRITICAL/HIGH Affecting Key Layers:\n")
		for _, layer := range criticalLayers {
			fmt.Fprintf(out, "  ⚠️  %s\n", layer)
		}
		fmt.Fprintf(out, "\n")
	}
}

func writeReleaseGateRecommendation(out io.Writer, gate ReleaseGate, reasons []string) {
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "4. RELEASE GATE RECOMMENDATION\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n\n")

	fmt.Fprintf(out, "%s\n\n", gate)

	if len(reasons) > 0 {
		fmt.Fprintf(out, "Justification:\n")
		for _, reason := range reasons {
			fmt.Fprintf(out, "  • %s\n", reason)
		}
	}
	fmt.Fprintf(out, "\n")

	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(out, "END OF REPORT\n")
	fmt.Fprintf(out, "═══════════════════════════════════════════════════════════════════════════════\n")
}

// Helper functions

func processVulnerabilities(result *types.ScanResult) []VulnEntry {
	var entries []VulnEntry

	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			env := "production"
			if dep.Type == types.Development {
				env = "dev"
			}

			exploitType := ClassifyExploitType(vuln)
			exploitability := AssessRuntimeExploitability(vuln, exploitType)
			action := DetermineRecommendedAction(vuln, dep.Type, exploitType, exploitability)

			entry := VulnEntry{
				Library:             dep.Name,
				Version:             dep.Version,
				Environment:         env,
				VulnID:              getVulnID(vuln),
				Severity:            vuln.Severity,
				CVSS:                vuln.CVSSScore,
				CVSSVector:          vuln.CVSSVector,
				ExploitType:         exploitType,
				Exploitability:      exploitability,
				DependencyPath:      fmt.Sprintf("%s@%s", dep.Name, dep.Version),
				TechnicalSummary:    sanitizeSummary(vuln.Summary, vuln.Description),
				FixStatus:           "No fix yet", // TODO: implement fix detection
				RecommendedAction:   action,
				OperationalRiskNote: generateOperationalNote(vuln, dep.Type, exploitType, exploitability),
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

func groupBySeverity(entries []VulnEntry) map[types.Severity][]VulnEntry {
	result := make(map[types.Severity][]VulnEntry)
	for _, entry := range entries {
		result[entry.Severity] = append(result[entry.Severity], entry)
	}
	return result
}

func analyzeSystemicRisks(result *types.ScanResult) map[string]interface{} {
	signals := make(map[string]interface{})

	// Count vulnerabilities per package
	pkgCount := make(map[string]int)
	for _, dep := range result.Dependencies {
		if len(dep.Vulnerabilities) > 0 {
			pkgCount[dep.Name] += len(dep.Vulnerabilities)
		}
	}

	// Find repeated vulnerable packages (>= 2 vulns)
	var repeatedPkgs []string
	var hotClusters []string
	for pkg, count := range pkgCount {
		if count >= 2 {
			repeatedPkgs = append(repeatedPkgs, fmt.Sprintf("%s (%d findings)", pkg, count))
			if count >= 3 {
				hotClusters = append(hotClusters, fmt.Sprintf("%s (%d findings)", pkg, count))
			}
		}
	}

	sort.Strings(repeatedPkgs)
	sort.Strings(hotClusters)

	if len(repeatedPkgs) > 0 {
		signals["repeated_packages"] = repeatedPkgs
	}
	if len(hotClusters) > 0 {
		signals["hot_clusters"] = hotClusters
	}

	// Detect critical layer impacts
	var criticalLayers []string
	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			if vuln.Severity == types.Critical || vuln.Severity == types.High {
				if detectsCriticalLayer(dep.Name, vuln) {
					layer := getCriticalLayer(dep.Name, vuln)
					if !contains(criticalLayers, layer) {
						criticalLayers = append(criticalLayers, layer)
					}
				}
			}
		}
	}

	if len(criticalLayers) > 0 {
		signals["critical_layers"] = criticalLayers
	}

	return signals
}

func determineReleaseGate(result *types.ScanResult, entries []VulnEntry) (ReleaseGate, []string) {
	var reasons []string

	// Block if any CRITICAL in production
	if result.CriticalVulns > 0 {
		prodCritical := 0
		for _, entry := range entries {
			if entry.Severity == types.Critical && entry.Environment == "production" {
				prodCritical++
			}
		}
		if prodCritical > 0 {
			reasons = append(reasons, fmt.Sprintf("%d CRITICAL vulnerabilities in production dependencies", prodCritical))
			reasons = append(reasons, "Immediate patching required before release")
			return ReleaseBlock, reasons
		}
	}

	// Block if multiple HIGH in production
	prodHigh := 0
	for _, entry := range entries {
		if entry.Severity == types.High && entry.Environment == "production" {
			prodHigh++
		}
	}
	if prodHigh >= 3 {
		reasons = append(reasons, fmt.Sprintf("%d HIGH severity vulnerabilities in production", prodHigh))
		reasons = append(reasons, "Multiple HIGH findings create unacceptable cumulative risk")
		return ReleaseBlock, reasons
	}

	// Allow with mitigations if HIGH or MEDIUM exists
	if result.HighVulns > 0 || result.MediumVulns > 0 {
		if prodHigh > 0 {
			reasons = append(reasons, fmt.Sprintf("%d HIGH findings manageable with monitoring", prodHigh))
		}
		if result.MediumVulns > 0 {
			reasons = append(reasons, fmt.Sprintf("%d MEDIUM findings acceptable with timeline for remediation", result.MediumVulns))
		}
		reasons = append(reasons, "Schedule fixes in next sprint")
		return ReleaseAllowWithMitigation, reasons
	}

	// Proceed if only LOW or dev-only
	reasons = append(reasons, "No CRITICAL or HIGH production vulnerabilities")
	if result.LowVulns > 0 {
		reasons = append(reasons, fmt.Sprintf("%d LOW findings represent acceptable background risk", result.LowVulns))
	}
	return ReleaseProceed, reasons
}

func getVulnID(vuln types.Vulnerability) string {
	if vuln.CVEID != "" {
		return vuln.CVEID
	}
	return vuln.ID
}

func sanitizeSummary(summary, description string) string {
	if summary != "" && len(summary) <= 200 {
		return summary
	}
	if description != "" && len(description) <= 200 {
		return description
	}
	if summary != "" {
		return summary[:197] + "..."
	}
	return "No description available"
}

func generateOperationalNote(vuln types.Vulnerability, depType types.DependencyType, exploitType ExploitType, exploitability RuntimeExploitability) string {
	var parts []string

	if depType == types.Production {
		parts = append(parts, "Affects production code")
	} else {
		parts = append(parts, "Dev/test dependency only")
	}

	if exploitType == ExploitRCE || exploitType == ExploitInjection {
		parts = append(parts, "potentially internet-exposed")
	}

	if exploitability == ExploitableYes {
		parts = append(parts, "high likelihood of exploitation")
	} else if exploitability == ExploitableConditional {
		parts = append(parts, "exploitable under specific conditions")
	}

	return strings.Join(parts, ", ") + "."
}

func detectsCriticalLayer(pkgName string, vuln types.Vulnerability) bool {
	combined := strings.ToLower(pkgName + " " + vuln.Summary)

	criticalKeywords := []string{
		"auth", "authentication", "passport", "jwt",
		"express", "fastify", "koa", "server",
		"serialize", "deserialize", "yaml", "xml",
		"template", "ejs", "pug", "handlebars",
		"fs", "file", "path",
	}

	for _, keyword := range criticalKeywords {
		if strings.Contains(combined, keyword) {
			return true
		}
	}
	return false
}

func getCriticalLayer(pkgName string, vuln types.Vulnerability) string {
	combined := strings.ToLower(pkgName + " " + vuln.Summary)

	if containsAny(combined, []string{"auth", "passport", "jwt"}) {
		return "Authentication Layer"
	}
	if containsAny(combined, []string{"express", "fastify", "koa", "server"}) {
		return "Network Layer"
	}
	if containsAny(combined, []string{"serialize", "deserialize", "yaml", "xml"}) {
		return "Deserialization"
	}
	if containsAny(combined, []string{"template", "ejs", "pug", "handlebars"}) {
		return "Template Engine"
	}
	if containsAny(combined, []string{"fs", "file", "path"}) {
		return "File System Access"
	}
	return "Other"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	// Simple wrap - can be enhanced
	return text[:width-3] + "..."
}
