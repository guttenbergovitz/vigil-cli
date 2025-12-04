package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/github"
	"github.com/guttenbergovitz/vigil-cli/internal/nvd"
	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/internal/scanner"
	"github.com/guttenbergovitz/vigil-cli/internal/ui"
	"github.com/guttenbergovitz/vigil-cli/pkg/export"
	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: vigil <command> [args]")
	}

	cmd := os.Args[1]

	switch cmd {
	case "scan":
		return cmdScan(os.Args[2:])
	case "report":
		return cmdReport(os.Args[2:])
	case "ci":
		return cmdCI(os.Args[2:])
	case "version":
		fmt.Println("vigil version 0.1.0")
		return nil
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	skipDevDeps := fs.Bool("skip-devdeps", false, "Skip development dependencies")
	outputFmt := fs.String("output", "", "Output format (json, csv, markdown)")
	noTUI := fs.Bool("no-tui", false, "Disable interactive TUI (useful for CI/testing)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("scan: missing project path argument")
	}

	projectPath := fs.Arg(0)

	// Resolve absolute path
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Find lock file
	lockFile, lockType, err := scanner.FindLockFile(absPath)
	if err != nil {
		return fmt.Errorf("no lock file found in %s: %w\n\nSupported lock files: package-lock.json (npm), yarn.lock (yarn), pnpm-lock.yaml (pnpm)", absPath, err)
	}

	lockFilePath := filepath.Join(absPath, lockFile)

	// Hash the lock file
	lockHash, err := scanner.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	// Channel for scan results
	resultChan := make(chan *models.ScanResult, 1)
	errorChan := make(chan error, 1)
	var wg sync.WaitGroup

	var program *tea.Program
	var finalModel tea.Model

	if !*noTUI {
		// Create Bubbletea model for progress display with alt screen
		model := ui.NewModel()
		program = tea.NewProgram(model, tea.WithAltScreen())
	}

	// Start scanning in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := performScan(absPath, lockFile, lockType, lockHash, lockFilePath, *skipDevDeps, program)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()

	// Run TUI if enabled
	if !*noTUI {
		var err error
		finalModel, err = program.Run()
		if err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
	} else {
		// In non-TUI mode, just print progress to stdout
		fmt.Println("Scanning...")
	}

	// Wait for scan to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Check for scan errors or results
	select {
	case err := <-errorChan:
		return err
	case result := <-resultChan:
		// Handle result
		var model *ui.Model
		if finalModel != nil {
			model = finalModel.(*ui.Model)
		}
		return handleScanResult(result, *outputFmt, model)
	case <-done:
		// Scan completed but no result was sent
		return fmt.Errorf("scan completed with no results")
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("scan timeout: took longer than 5 minutes")
	}
}

// sendToTUI sends a message to the TUI program if it exists
func sendToTUI(program *tea.Program, msg tea.Msg) {
	if program != nil {
		program.Send(msg)
	}
}

// performScan runs the actual scanning with progress updates
func performScan(absPath, lockFile string, lockType scanner.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, program *tea.Program) (*models.ScanResult, error) {
	// Check if lock file path is valid
	if lockFilePath == "" || lockFile == "" {
		errMsg := "No lock file found. Please run this in a Node.js/TypeScript project with package-lock.json, yarn.lock, or pnpm-lock.yaml"
		sendToTUI(program, ui.ErrorMsg{Err: errMsg})
		return nil, fmt.Errorf("%s", errMsg)
	}

	// Parse lock file and build dependency graph
	lockf, err := os.Open(lockFilePath)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to open lock file: %v", err)
		sendToTUI(program, ui.ErrorMsg{Err: errMsg})
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockf.Close()

	var graph *models.DependencyGraph

	if lockType == scanner.PnpmLock {
		graph, err = scanner.ParsePnpmLockGraph(lockf)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to parse pnpm-lock.yaml: %v", err)
			sendToTUI(program, ui.ErrorMsg{Err: errMsg})
			return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
		}
	} else {
		deps, err := scanner.ParseLockFile(lockf, lockType)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to parse lock file: %v", err)
			sendToTUI(program, ui.ErrorMsg{Err: errMsg})
			return nil, fmt.Errorf("failed to parse lock file: %w", err)
		}

		depTree, err := scanner.BuildDependencyTree(deps)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to build dependency tree: %v", err)
			sendToTUI(program, ui.ErrorMsg{Err: errMsg})
			return nil, fmt.Errorf("failed to build dependency tree: %w", err)
		}

		graph = models.NewDependencyGraph()
		for _, dep := range depTree {
			graph.AddNode(dep.Name, dep.Version, dep.Type, true)
			graph.Root = append(graph.Root, dep.Name+"@"+dep.Version)
		}
		graph.CalculateDepths()
	}

	// Check if graph has any nodes
	if len(graph.Nodes) == 0 {
		errMsg := "No dependencies found in lock file. The project may have no dependencies or the lock file is empty."
		sendToTUI(program, ui.ErrorMsg{Err: errMsg})
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
	var nodesToScanList []*models.DependencyNode
	for _, node := range graph.Nodes {
		if skipDevDeps && node.Type == models.Development {
			continue
		}
		nodesToScan++
		nodesToScanList = append(nodesToScanList, node)
	}

	fmt.Fprintf(os.Stderr, "DEBUG: Will scan %d nodes sequentially\n", nodesToScan)

	// Send initial progress with total
	sendToTUI(program, ui.ProgressMsg{
		Progress: ui.ScanProgress{
			Current:      0,
			Total:        nodesToScan,
			CurrentPkg:   "Starting scan...",
			CurrentVulns: 0,
		},
	})

	totalVulns := 0

	// Scan packages sequentially
	for current, node := range nodesToScanList {
		// Send progress update
		sendToTUI(program, ui.ProgressMsg{
			Progress: ui.ScanProgress{
				Current:      current + 1,
				Total:        nodesToScan,
				CurrentPkg:   node.Name + "@" + node.Version,
				CurrentVulns: totalVulns,
			},
		})

		// Query OSV API for this package
		vulns, err := osvClient.Query(node.Name, node.Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: Error scanning %s@%s: %v\n", node.Name, node.Version, err)
			continue
		}

		// Process vulnerabilities
		for j := range vulns {
			vulns[j].RiskScore = osv.CalculateRiskScoreWithDepth(
				vulns[j].Severity,
				node.Type == models.Production,
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

			// Determine display CVE ID (prefer CVE-* over GHSA-*)
			displayCVE := vulns[j].ID
			if vulns[j].CVEID != "" {
				displayCVE = vulns[j].CVEID
			}

			// Determine display severity (prefer CVESeverity from NVD if available)
			displaySeverity := string(vulns[j].Severity)
			if vulns[j].CVESeverity != "" {
				displaySeverity = string(vulns[j].CVESeverity)
			}
			// Ensure severity is not empty
			if displaySeverity == "" {
				displaySeverity = "unknown"
			}

			// Format published date
			publishedStr := ""
			if vulns[j].PublishedAt != nil {
				publishedStr = vulns[j].PublishedAt.Format("2006-01-02")
			}

			// CVSS score should already be set from OSV or NVD
			displayCVSS := vulns[j].CVSSScore

			// Send vulnerability to TUI for dynamic display
			sendToTUI(program, ui.VulnMsg{
				Entry: ui.VulnEntry{
					Package:        node.Name + "@" + node.Version,
					CVE:            displayCVE,
					CVEID:          vulns[j].CVEID,
					Severity:       displaySeverity,
					CVSS:           displayCVSS,
					Description:    vulns[j].Summary,
					CVETitle:       vulns[j].CVETitle,
					CVEDescription: vulns[j].CVEDescription,
					PublishedAt:    publishedStr,
					DependencyPath: dependencyPath,
				},
			})

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
		// This helps avoid rate limiting
		time.Sleep(10 * time.Millisecond)
	}

	// Build result
	result := buildScanResultFromGraph(absPath, lockFile, lockHash, graph)

	// Send completion with results
	sendToTUI(program, ui.DoneMsg{
		Result: &ui.ScanResult{
			TotalVulns:    result.TotalVulns,
			CriticalVulns: result.CriticalVulns,
			HighVulns:     result.HighVulns,
			MediumVulns:   result.MediumVulns,
			LowVulns:      result.LowVulns,
		},
	})

	// Save cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	if err := scanner.SaveCache(cachePath, result); err != nil {
		return nil, fmt.Errorf("save cache: %w", err)
	}

	return result, nil
}

// handleScanResult displays results and handles output
func handleScanResult(result *models.ScanResult, outputFmt string, finalModel *ui.Model) error {
	if outputFmt != "" {
		switch outputFmt {
		case "csv":
			if err := export.CSV(result, os.Stdout); err != nil {
				return err
			}
		case "markdown":
			if err := export.Markdown(result, os.Stdout); err != nil {
				return err
			}
		case "json":
			if err := export.JSON(result, os.Stdout); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown output format: %s", outputFmt)
		}
	} else {
		// Print summary
		fmt.Printf("\n✓ Scan complete: %d dependencies, %d vulnerabilities\n",
			len(result.Dependencies), result.TotalVulns)
		if result.CriticalVulns > 0 {
			fmt.Printf("  🔴 Critical: %d\n", result.CriticalVulns)
		}
		if result.HighVulns > 0 {
			fmt.Printf("  🟠 High: %d\n", result.HighVulns)
		}
		if result.MediumVulns > 0 {
			fmt.Printf("  🟡 Medium: %d\n", result.MediumVulns)
		}
	}

	if result.CriticalVulns > 0 || result.HighVulns > 0 {
		os.Exit(1)
	}

	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	format := fs.String("format", "text", "Output format (text, csv, markdown)")
	exportFile := fs.String("export", "", "Export to file")
	filterLevel := fs.String("filter", "", "Filter by severity level (low, medium, high, critical)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	// Get project path (current directory by default, or first arg if provided)
	projectPath := "./"
	if fs.NArg() > 0 {
		projectPath = fs.Arg(0)
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Load cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	result, err := scanner.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	// Filter results if requested
	if *filterLevel != "" {
		result = filterByLevel(result, *filterLevel)
	}

	// Determine output destination
	var out *os.File = os.Stdout
	if *exportFile != "" {
		f, err := os.Create(*exportFile)
		if err != nil {
			return fmt.Errorf("create export file: %w", err)
		}
		defer f.Close()
		out = f
	}

	// Generate report in requested format
	switch *format {
	case "text":
		return reportText(result, out)
	case "csv":
		return export.CSV(result, out)
	case "markdown":
		return export.Markdown(result, out)
	case "json":
		return export.JSON(result, out)
	default:
		return fmt.Errorf("unknown format: %s", *format)
	}
}

// filterByLevel filters scan results to show only vulns at or above specified level
func filterByLevel(result *models.ScanResult, level string) *models.ScanResult {
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

// reportText generates a text report with supply chain context
func reportText(result *models.ScanResult, out *os.File) error {
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

func cmdCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	failOn := fs.String("fail-on", "high", "Fail if vulns at or above level (low, medium, high, critical)")
	failOnCVSS := fs.Float64("fail-on-cvss", 0.0, "Fail if any vuln has CVSS >= this threshold (0.0-10.0)")
	format := fs.String("format", "text", "Output format (text, csv, markdown, json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	// Validate CVSS threshold
	if *failOnCVSS < 0.0 || *failOnCVSS > 10.0 {
		return fmt.Errorf("invalid CVSS threshold: must be between 0.0 and 10.0")
	}

	// Get project path (current directory by default, or first arg if provided)
	projectPath := "./"
	if fs.NArg() > 0 {
		projectPath = fs.Arg(0)
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Load cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	result, err := scanner.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	// Determine fail threshold
	severityMap := map[string]models.Severity{
		"low":      models.Low,
		"medium":   models.Medium,
		"high":     models.High,
		"critical": models.Critical,
	}

	minSev, ok := severityMap[*failOn]
	if !ok {
		return fmt.Errorf("invalid fail-on level: %s", *failOn)
	}

	severityOrder := map[models.Severity]int{
		models.Low:      1,
		models.Medium:   2,
		models.High:     3,
		models.Critical: 4,
	}

	// Check if vulnerabilities at or above threshold exist
	failCount := 0
	cvssFailCount := 0

	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			// Check severity threshold
			if severityOrder[vuln.Severity] >= severityOrder[minSev] {
				failCount++
			}

			// Check CVSS threshold (if specified and CVSS is available)
			if *failOnCVSS > 0.0 && vuln.CVSSScore >= *failOnCVSS {
				cvssFailCount++
			}
		}
	}

	// Output summary
	switch *format {
	case "text":
		if *failOnCVSS > 0.0 {
			fmt.Printf("CI Check: severity=%s, CVSS>=%.1f\n", *failOn, *failOnCVSS)
			if failCount == 0 && cvssFailCount == 0 {
				fmt.Printf("✓ No critical vulnerabilities found\n")
				return nil
			}
			if failCount > 0 {
				fmt.Printf("✗ Found %d vulns at or above %s level\n", failCount, *failOn)
			}
			if cvssFailCount > 0 {
				fmt.Printf("✗ Found %d vulns with CVSS >= %.1f\n", cvssFailCount, *failOnCVSS)
			}
		} else {
			fmt.Printf("CI Check: %s and above\n", *failOn)
			if failCount == 0 {
				fmt.Printf("✓ No vulnerabilities at or above %s level\n", *failOn)
				return nil
			}
			fmt.Printf("✗ Found %d vulnerabilities at or above %s level\n", failCount, *failOn)
		}
		os.Exit(1)
	case "json":
		export.JSON(result, os.Stdout)
	case "csv":
		export.CSV(result, os.Stdout)
	case "markdown":
		export.Markdown(result, os.Stdout)
	default:
		return fmt.Errorf("unknown format: %s", *format)
	}

	// Exit with code 1 if vulns found
	if failCount > 0 || cvssFailCount > 0 {
		os.Exit(1)
	}

	return nil
}

func buildScanResultFromGraph(projectPath, lockFile, lockHash string, graph *models.DependencyGraph) *models.ScanResult {
	// Convert graph nodes to flat dependency list
	deps := make([]models.Dependency, 0, len(graph.Nodes))

	for _, node := range graph.Nodes {
		dep := models.Dependency{
			Name:            node.Name,
			Version:         node.Version,
			Type:            node.Type,
			Vulnerabilities: node.Vulnerabilities,
		}
		deps = append(deps, dep)
	}

	result := &models.ScanResult{
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
			case models.Critical:
				result.CriticalVulns++
			case models.High:
				result.HighVulns++
			case models.Medium:
				result.MediumVulns++
			case models.Low:
				result.LowVulns++
			}
		}
	}

	return result
}

// truncateText limits text length and adds ellipsis if needed
func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "…"
}

// deriveCVSSFromSeverity derives a CVSS score from severity level as last resort
// This ensures we always have some score even if no source provides one
func deriveCVSSFromSeverity(severity models.Severity) float64 {
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
func severityFromCVSS(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.Critical
	case score >= 7.0:
		return models.High
	case score >= 4.0:
		return models.Medium
	case score > 0:
		return models.Low
	default:
		return models.Medium
	}
}
