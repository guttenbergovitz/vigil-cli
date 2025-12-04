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
				StartTime:    time.Now(),
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
		}

		node.Vulnerabilities = vulns
		totalVulns += len(vulns)
	}

	// Send completion
	program.Send(ui.DoneMsg{})

	// Build result
	result := buildScanResultFromGraph(absPath, lockFile, lockHash, graph)

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
	return fmt.Errorf("report not implemented")
}

func cmdCI(args []string) error {
	return fmt.Errorf("ci not implemented")
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
