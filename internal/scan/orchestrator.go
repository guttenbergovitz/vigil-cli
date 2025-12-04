package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/github"
	"github.com/guttenbergovitz/vigil-cli/internal/nvd"
	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ProgressReporter defines how the orchestrator reports progress to the UI
type ProgressReporter interface {
	Error(msg string)
	Progress(current, total int, currentPkg string, currentVulns int)
	Vulnerability(vuln types.Vulnerability, pkg string, path []string)
	Done(result *types.ScanResult)
}

// Scan performs the vulnerability scan
func Scan(absPath, lockFile string, lockType lockfile.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, reporter ProgressReporter) (*types.ScanResult, error) {
	// Check if lock file path is valid
	if lockFilePath == "" || lockFile == "" {
		errMsg := "No lock file found. Please run this in a Node.js/TypeScript project with package-lock.json, yarn.lock, or pnpm-lock.yaml"
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Parse lock file and build dependency graph
	lockf, err := os.Open(lockFilePath)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to open lock file: %v", err)
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockf.Close()

	var graph *types.DependencyGraph

	if lockType == lockfile.PnpmLock {
		graph, err = lockfile.ParsePnpmLockGraph(lockf)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to parse pnpm-lock.yaml: %v", err)
			if reporter != nil {
				reporter.Error(errMsg)
			}
			return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
		}
	} else {
		deps, err := lockfile.ParseLockFile(lockf, lockType)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to parse lock file: %v", err)
			if reporter != nil {
				reporter.Error(errMsg)
			}
			return nil, fmt.Errorf("failed to parse lock file: %w", err)
		}

		depTree, err := lockfile.BuildDependencyTree(deps)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to build dependency tree: %v", err)
			if reporter != nil {
				reporter.Error(errMsg)
			}
			return nil, fmt.Errorf("failed to build dependency tree: %w", err)
		}

		graph = types.NewDependencyGraph()
		for _, dep := range depTree {
			graph.AddNode(dep.Name, dep.Version, dep.Type, true)
			graph.Root = append(graph.Root, dep.Name+"@"+dep.Version)
		}
		graph.CalculateDepths()
	}

	// Check if graph has any nodes
	if len(graph.Nodes) == 0 {
		errMsg := "No dependencies found in lock file. The project may have no dependencies or the lock file is empty."
		if reporter != nil {
			reporter.Error(errMsg)
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Scan all dependencies sequentially to respect API rate limits
	osvClient := osv.New("https://api.osv.dev/v1/query", 10)

	// Initialize NVD client with API key from environment
	nvdAPIKey := os.Getenv("NVD_API_KEY")
	nvdClient := nvd.New("https://services.nvd.nist.gov/rest/json/cves/2.0", nvdAPIKey, 10)

	// Initialize GitHub client (token optional; falls back to public API)
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubClient := github.New(githubToken, 10)

	// Count nodes to scan and collect them
	nodesToScan := 0
	var nodesToScanList []*types.DependencyNode
	for _, node := range graph.Nodes {
		if skipDevDeps && node.Type == types.Development {
			continue
		}
		nodesToScan++
		nodesToScanList = append(nodesToScanList, node)
	}

	// Send initial progress with total
	if reporter != nil {
		reporter.Progress(0, nodesToScan, "Starting scan...", 0)
	}

	totalVulns := 0

	// Scan packages sequentially
	for current, node := range nodesToScanList {
		// Send progress update
		if reporter != nil {
			reporter.Progress(current+1, nodesToScan, node.Name+"@"+node.Version, totalVulns)
		}

		// Query OSV API for this package
		vulns, err := osvClient.Query(node.Name, node.Version)
		if err != nil {
			// Log error but continue
			// fmt.Fprintf(os.Stderr, "DEBUG: Error scanning %s@%s: %v\n", node.Name, node.Version, err)
			continue
		}

		// Process vulnerabilities
		for j := range vulns {
			vulns[j].RiskScore = osv.CalculateRiskScoreWithDepth(
				vulns[j].Severity,
				node.Type == types.Production,
				node.Depth,
			)

			// Get full dependency path from root
			nodeKey := node.Name + "@" + node.Version
			dependencyPath := graph.GetVulnerablePath(nodeKey)

			// Try multiple sources for CVSS score (priority: NVD > GitHub > OSV > derived from severity)
			originalCVSS := vulns[j].CVSSScore

			// 1. Try NVD API for CVE-* IDs
			if vulns[j].CVEID != "" && strings.HasPrefix(vulns[j].CVEID, "CVE-") {
				nvdVuln, err := nvdClient.QueryCVE(vulns[j].CVEID)
				if err == nil && nvdVuln != nil {
					// Enrich with NVD data
					vulns[j].CVETitle = nvdVuln.CVETitle
					vulns[j].CVEDescription = nvdVuln.CVEDescription
					// Use NVD severity if available (it's more authoritative for CVE)
					if nvdVuln.CVESeverity != "" {
						vulns[j].CVESeverity = nvdVuln.CVESeverity
						vulns[j].Severity = nvdVuln.CVESeverity // Override with NVD severity
					}
					// Always use NVD CVSS score if available (NVD is authoritative for CVE)
					if nvdVuln.CVSSScore > 0 {
						vulns[j].CVSSScore = nvdVuln.CVSSScore
						vulns[j].CVSSVector = nvdVuln.CVSSVector
					}
				}
			}

			// 2. If still no CVSS and it's a GHSA-*, try GitHub Security Advisories API
			if vulns[j].CVSSScore == 0 && strings.HasPrefix(vulns[j].ID, "GHSA-") {
				if githubClient != nil {
					ghsaVuln, err := githubClient.QueryGHSA(vulns[j].ID)
					if err == nil && ghsaVuln != nil && ghsaVuln.CVSSScore > 0 {
						vulns[j].CVSSScore = ghsaVuln.CVSSScore
						vulns[j].CVSSVector = ghsaVuln.CVSSVector
						if vulns[j].CVETitle == "" {
							vulns[j].CVETitle = ghsaVuln.Summary
						}
						if vulns[j].CVEDescription == "" {
							vulns[j].CVEDescription = ghsaVuln.Description
						}
						// Use GHSA severity if we don't have a better one
						if ghsaVuln.Severity != "" {
							vulns[j].Severity = ghsaVuln.Severity
							vulns[j].CVESeverity = ghsaVuln.Severity
						}
					}
				}
			}

			// 3. If still no CVSS, use OSV CVSS (should already be set, but ensure it's used)
			if vulns[j].CVSSScore == 0 && originalCVSS > 0 {
				vulns[j].CVSSScore = originalCVSS
			}

			// 4. If still no CVSS, derive from severity as last resort
			if vulns[j].CVSSScore == 0 {
				vulns[j].CVSSScore = deriveCVSSFromSeverity(vulns[j].Severity)
			}

			// 5. If CVSS is present but severity is weak/unknown, derive severity from CVSS
			if vulns[j].CVSSScore > 0 {
				derivedSev := severityFromCVSS(vulns[j].CVSSScore)
				if vulns[j].Severity == "" || strings.EqualFold(string(vulns[j].Severity), "medium") || strings.EqualFold(string(vulns[j].Severity), "unknown") {
					vulns[j].Severity = derivedSev
				}
				if vulns[j].CVESeverity == "" {
					vulns[j].CVESeverity = derivedSev
				}
			}

			// Send vulnerability to TUI for dynamic display
			if reporter != nil {
				reporter.Vulnerability(vulns[j], node.Name+"@"+node.Version, dependencyPath)
			}

			// Rate limit NVD API calls (5 req/30s without key, 50 req/30s with key)
			if vulns[j].CVEID != "" && strings.HasPrefix(vulns[j].CVEID, "CVE-") {
				if nvdAPIKey == "" {
					time.Sleep(6 * time.Second) // 5 req/30s = 6s between requests
				} else {
					time.Sleep(600 * time.Millisecond) // 50 req/30s = 600ms between requests
				}
			}
		}

		node.Vulnerabilities = vulns
		totalVulns += len(vulns)

		// Be respectful to the API - add a small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	// Build result
	result := buildScanResultFromGraph(absPath, lockFile, lockHash, graph)

	// Send completion with results
	if reporter != nil {
		reporter.Done(result)
	}

	// Save cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	if err := lockfile.SaveCache(cachePath, result); err != nil {
		return nil, fmt.Errorf("save cache: %w", err)
	}

	return result, nil
}

func buildScanResultFromGraph(projectPath, lockFile, lockHash string, graph *types.DependencyGraph) *types.ScanResult {
	// Convert graph nodes to flat dependency list
	deps := make([]types.Dependency, 0, len(graph.Nodes))

	for _, node := range graph.Nodes {
		dep := types.Dependency{
			Name:            node.Name,
			Version:         node.Version,
			Type:            node.Type,
			Vulnerabilities: node.Vulnerabilities,
		}
		deps = append(deps, dep)
	}

	result := &types.ScanResult{
		Version:      1,
		ProjectPath:  projectPath,
		ScannedAt:    time.Now().UTC(),
		LockFile:     lockFile,
		LockFileHash: lockHash,
		Dependencies: deps,
	}

	// Count vulnerabilities by severity (use CVESeverity from NVD if available)
	for _, node := range graph.Nodes {
		for _, vuln := range node.Vulnerabilities {
			result.TotalVulns++
			// Use CVESeverity from NVD if available, otherwise use Severity
			severity := vuln.Severity
			if vuln.CVESeverity != "" {
				severity = vuln.CVESeverity
			}
			switch severity {
			case types.Critical:
				result.CriticalVulns++
			case types.High:
				result.HighVulns++
			case types.Medium:
				result.MediumVulns++
			case types.Low:
				result.LowVulns++
			}
		}
	}

	return result
}

// deriveCVSSFromSeverity derives a CVSS score from severity level as last resort
func deriveCVSSFromSeverity(severity types.Severity) float64 {
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

// severityFromCVSS maps CVSS score to severity
func severityFromCVSS(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.Critical
	case score >= 7.0:
		return types.High
	case score >= 4.0:
		return types.Medium
	case score > 0:
		return types.Low
	default:
		return types.Medium
	}
}
