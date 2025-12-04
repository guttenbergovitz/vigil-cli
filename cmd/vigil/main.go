package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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
		return err
	}

	lockFilePath := filepath.Join(absPath, lockFile)

	// Hash the lock file
	lockHash, err := scanner.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	// Create Bubbletea model for progress display
	model := ui.NewModel()
	program := tea.NewProgram(model)

	// Channel for scan results
	resultChan := make(chan *models.ScanResult, 1)
	errorChan := make(chan error, 1)
	var wg sync.WaitGroup

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

	// Run TUI
	finalModel, err := program.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// Wait for scan to complete
	wg.Wait()

	// Check for scan errors
	select {
	case err := <-errorChan:
		return err
	case result := <-resultChan:
		// Handle result
		return handleScanResult(result, *outputFmt, finalModel.(ui.Model))
	}
}

// performScan runs the actual scanning with progress updates
func performScan(absPath, lockFile string, lockType scanner.LockFileType, lockHash, lockFilePath string, skipDevDeps bool, program *tea.Program) (*models.ScanResult, error) {
	// Parse lock file and build dependency graph
	lockf, err := os.Open(lockFilePath)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	defer lockf.Close()

	var graph *models.DependencyGraph

	if lockType == scanner.PnpmLock {
		graph, err = scanner.ParsePnpmLockGraph(lockf)
		if err != nil {
			return nil, fmt.Errorf("parse lock file graph: %w", err)
		}
	} else {
		deps, err := scanner.ParseLockFile(lockf, lockType)
		if err != nil {
			return nil, fmt.Errorf("parse lock file: %w", err)
		}

		depTree, err := scanner.BuildDependencyTree(deps)
		if err != nil {
			return nil, fmt.Errorf("build tree: %w", err)
		}

		graph = models.NewDependencyGraph()
		for _, dep := range depTree {
			graph.AddNode(dep.Name, dep.Version, dep.Type, true)
			graph.Root = append(graph.Root, dep.Name+"@"+dep.Version)
		}
		graph.CalculateDepths()
	}

	// Scan all dependencies with progress updates
	osvClient := osv.New("https://api.osv.dev/v1/query", 10)
	totalVulns := 0
	current := 0

	for _, node := range graph.Nodes {
		if skipDevDeps && node.Type == models.Development {
			continue
		}

		current++

		// Send progress update
		program.Send(ui.ProgressMsg{
			Progress: ui.ScanProgress{
				Current:      current,
				Total:        len(graph.Nodes),
				CurrentPkg:   node.Name + "@" + node.Version,
				CurrentVulns: totalVulns,
			},
		})

		vulns, err := osvClient.Query(node.Name, node.Version)
		if err != nil {
			continue
		}

		for j := range vulns {
			vulns[j].RiskScore = osv.CalculateRiskScoreWithDepth(
				vulns[j].Severity,
				node.Type == models.Production,
				node.Depth,
			)

			// Send vulnerability to TUI for dynamic display
			program.Send(ui.VulnMsg{
				Entry: ui.VulnEntry{
					Package:  node.Name + "@" + node.Version,
					CVE:      vulns[j].ID,
					Severity: string(vulns[j].Severity),
					CVSS:     vulns[j].CVSSScore,
				},
			})
		}

		node.Vulnerabilities = vulns
		totalVulns += len(vulns)
	}

	// Build result
	result := buildScanResultFromGraph(absPath, lockFile, lockHash, graph)

	// Send completion with results
	program.Send(ui.DoneMsg{
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
func handleScanResult(result *models.ScanResult, outputFmt string, finalModel ui.Model) error {
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
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0\n", vuln.CVSSScore)
					}
					fmt.Fprintf(out, "│   └── %s\n", vuln.Summary)
					if vuln.RiskScore > 0 {
						fmt.Fprintf(out, "│       Risk Score: %d/100\n", vuln.RiskScore)
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
						fmt.Fprintf(out, "│   ├── CVSS: %.1f/10.0\n", vuln.CVSSScore)
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
						fmt.Fprintf(out, "│   └── CVSS: %.1f/10.0\n", vuln.CVSSScore)
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
						fmt.Fprintf(out, "│   └── CVSS: %.1f/10.0\n", vuln.CVSSScore)
					}
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
	format := fs.String("format", "text", "Output format (text, csv, markdown, json)")

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
	for _, dep := range result.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			if severityOrder[vuln.Severity] >= severityOrder[minSev] {
				failCount++
			}
		}
	}

	// Output summary
	switch *format {
	case "text":
		fmt.Printf("CI Check: %s and above\n", *failOn)
		if failCount == 0 {
			fmt.Printf("✓ No vulnerabilities at or above %s level\n", *failOn)
			return nil
		}
		fmt.Printf("✗ Found %d vulnerabilities at or above %s level\n", failCount, *failOn)
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
	if failCount > 0 {
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

	// Count vulnerabilities by severity
	for _, node := range graph.Nodes {
		for _, vuln := range node.Vulnerabilities {
			result.TotalVulns++
			switch vuln.Severity {
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
