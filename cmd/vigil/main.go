package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/internal/scanner"
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
	lockFile, err := scanner.FindLockFile(absPath)
	if err != nil {
		return err
	}

	lockFilePath := filepath.Join(absPath, lockFile)

	// Hash the lock file
	lockHash, err := scanner.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	// Parse lock file
	lockf, err := os.Open(lockFilePath)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lockf.Close()

	deps, err := scanner.ParseNPMLock(lockf)
	if err != nil {
		return fmt.Errorf("parse lock file: %w", err)
	}

	// Build dependency tree
	depTree, err := scanner.BuildDependencyTree(deps)
	if err != nil {
		return fmt.Errorf("build tree: %w", err)
	}

	// Query OSV for each dependency
	osvClient := osv.New("https://api.osv.dev/v1/query", 10)

	for i := range depTree {
		// Skip dev dependencies if requested
		if *skipDevDeps && depTree[i].Type == "development" {
			continue
		}

		vulns, err := osvClient.Query(depTree[i].Name, depTree[i].Version)
		if err != nil {
			// Log but continue scanning other packages
			fmt.Fprintf(os.Stderr, "warning: query %s@%s: %v\n", depTree[i].Name, depTree[i].Version, err)
			continue
		}

		// Calculate risk scores and count
		for j := range vulns {
			vulns[j].RiskScore = osv.CalculateRiskScore(vulns[j].Severity, depTree[i].Type == "production")
		}

		depTree[i].Vulnerabilities = vulns
	}

	// Build result
	result := buildScanResult(absPath, lockFile, lockHash, depTree)

	// Save cache
	cachePath := filepath.Join(absPath, ".vigil.cache")
	if err := scanner.SaveCache(cachePath, result); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}

	// Export if requested
	if *outputFmt != "" {
		switch *outputFmt {
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
			return fmt.Errorf("unknown output format: %s", *outputFmt)
		}
	} else {
		// Print summary
		fmt.Printf("Scan complete: %d dependencies, %d vulnerabilities\n",
			len(depTree), result.TotalVulns)
	}

	// Exit with status based on vulnerabilities
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

func buildScanResult(projectPath, lockFile, lockHash string, deps []models.Dependency) *models.ScanResult {
	result := &models.ScanResult{
		Version:      1,
		ProjectPath:  projectPath,
		ScannedAt:    time.Now().UTC(),
		LockFile:     lockFile,
		LockFileHash: lockHash,
		Dependencies: deps,
	}

	// Count vulnerabilities by severity
	for _, dep := range deps {
		for _, vuln := range dep.Vulnerabilities {
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
