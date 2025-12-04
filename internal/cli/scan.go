package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/orchestrator"
	"github.com/guttenbergovitz/vigil-cli/internal/scanner"
	"github.com/guttenbergovitz/vigil-cli/internal/ui"
	"github.com/guttenbergovitz/vigil-cli/pkg/export"
	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// Scan executes the scan command
func Scan(args []string) error {
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
	var reporter orchestrator.ProgressReporter

	if !*noTUI {
		// Create Bubbletea model for progress display with alt screen
		model := ui.NewModel()
		program = tea.NewProgram(model, tea.WithAltScreen())
		reporter = &TUIAdapter{program: program}
	} else {
		// In non-TUI mode, use a simple stdout reporter or nil
		// For now, we'll just print "Scanning..." as in original code
		fmt.Println("Scanning...")
		// We could implement a StdoutReporter here if needed
	}

	// Start scanning in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := orchestrator.Scan(absPath, lockFile, lockType, lockHash, lockFilePath, *skipDevDeps, reporter)
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

// TUIAdapter adapts the orchestrator.ProgressReporter interface to Bubbletea messages
type TUIAdapter struct {
	program *tea.Program
}

func (t *TUIAdapter) Error(msg string) {
	if t.program != nil {
		t.program.Send(ui.ErrorMsg{Err: msg})
	}
}

func (t *TUIAdapter) Progress(current, total int, currentPkg string, currentVulns int) {
	if t.program != nil {
		t.program.Send(ui.ProgressMsg{
			Progress: ui.ScanProgress{
				Current:      current,
				Total:        total,
				CurrentPkg:   currentPkg,
				CurrentVulns: currentVulns,
			},
		})
	}
}

func (t *TUIAdapter) Vulnerability(vuln models.Vulnerability, pkg string, path []string) {
	if t.program != nil {
		// Determine display CVE ID (prefer CVE-* over GHSA-*)
		displayCVE := vuln.ID
		if vuln.CVEID != "" {
			displayCVE = vuln.CVEID
		}

		// Determine display severity (prefer CVESeverity from NVD if available)
		displaySeverity := string(vuln.Severity)
		if vuln.CVESeverity != "" {
			displaySeverity = string(vuln.CVESeverity)
		}
		if displaySeverity == "" {
			displaySeverity = "unknown"
		}

		// Format published date
		publishedStr := ""
		if vuln.PublishedAt != nil {
			publishedStr = vuln.PublishedAt.Format("2006-01-02")
		}

		t.program.Send(ui.VulnMsg{
			Entry: ui.VulnEntry{
				Package:        pkg,
				CVE:            displayCVE,
				CVEID:          vuln.CVEID,
				Severity:       displaySeverity,
				CVSS:           vuln.CVSSScore,
				Description:    vuln.Summary,
				CVETitle:       vuln.CVETitle,
				CVEDescription: vuln.CVEDescription,
				PublishedAt:    publishedStr,
				DependencyPath: path,
			},
		})
	}
}

func (t *TUIAdapter) Done(result *models.ScanResult) {
	if t.program != nil {
		t.program.Send(ui.DoneMsg{
			Result: &ui.ScanResult{
				TotalVulns:    result.TotalVulns,
				CriticalVulns: result.CriticalVulns,
				HighVulns:     result.HighVulns,
				MediumVulns:   result.MediumVulns,
				LowVulns:      result.LowVulns,
			},
		})
	}
}
