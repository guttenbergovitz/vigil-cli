package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/git"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/scan"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
	"github.com/guttenbergovitz/vigil-cli/internal/ui"
)

// Scan executes the scan command
func Scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	skipDevDeps := fs.Bool("skip-devdeps", false, "Skip development dependencies")
	outputFmt := fs.String("output", "", "Output format (json, csv, markdown)")
	noTUI := fs.Bool("no-tui", false, "Disable interactive TUI (useful for CI/testing)")
	customLockFile := fs.String("lockfile", "", "Explicitly specify lockfile name (e.g. uv.lock, requirements.txt)")
	scanSecrets := fs.Bool("secrets", false, "Scan codebase for hardcoded secrets and leaked credentials")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("scan: missing project path argument")
	}

	projectPath := fs.Arg(0)

	var absPath string
	var cleanup func()

	// Check if projectPath is a git URL
	if git.IsGitURL(projectPath) {
		fmt.Printf("Cloning repository: %s\n", projectPath)
		clonedPath, cleanupFn, err := git.CloneToTemp(projectPath)
		if err != nil {
			return fmt.Errorf("clone repository: %w", err)
		}
		absPath = clonedPath
		cleanup = cleanupFn
		defer cleanup()
		fmt.Printf("Repository cloned to: %s\n", absPath)
	} else {
		// Resolve absolute path for local directory
		var err error
		absPath, err = filepath.Abs(projectPath)
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
	}

	var lockFile string
	var lockType lockfile.LockFileType

	if *customLockFile != "" {
		lockFile = *customLockFile
		switch lockFile {
		case "uv.lock":
			lockType = lockfile.UVLock
		case "poetry.lock":
			lockType = lockfile.PoetryLock
		case "Pipfile.lock":
			lockType = lockfile.PipfileLock
		case "requirements.txt":
			lockType = lockfile.RequirementsTxt
		case "package-lock.json":
			lockType = lockfile.NPMLock
		case "yarn.lock":
			lockType = lockfile.YarnLock
		case "pnpm-lock.yaml":
			lockType = lockfile.PnpmLock
		case "Cargo.lock":
			lockType = lockfile.CargoLock
		case "composer.lock":
			lockType = lockfile.ComposerLock
		case "go.mod":
			lockType = lockfile.GoModLock
		default:
			return fmt.Errorf("unsupported custom lock file: %s", lockFile)
		}
	} else {
		// Find lock file automatically
		var err error
		lockFile, lockType, err = lockfile.FindLockFile(absPath)
		if err != nil {
			return fmt.Errorf("no lock file found in %s: %w\n\nSupported lock files: uv.lock, poetry.lock, Pipfile.lock, requirements.txt, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, composer.lock, go.mod", absPath, err)
		}
	}

	lockFilePath := filepath.Join(absPath, lockFile)

	// Hash the lock file
	lockHash, err := lockfile.HashFile(lockFilePath)
	if err != nil {
		return fmt.Errorf("hash lock file: %w", err)
	}

	// Channel for scan results
	resultChan := make(chan *types.ScanResult, 1)
	errorChan := make(chan error, 1)
	var wg sync.WaitGroup

	var program *tea.Program
	var finalModel tea.Model
	var reporter scan.ProgressReporter

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
		result, err := scan.Scan(absPath, lockFile, lockType, lockHash, lockFilePath, *skipDevDeps, reporter)
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
		secList, _ := secrets.NewScanner().ScanDirectory(absPath)
		iacList, _ := container.AuditProject(absPath)
		licList := license.AnalyzeGraphLicenses(nil, nil)

		// Handle secret scanning if requested or in TUI
		if *scanSecrets || finalModel != nil {
			result.SecretCount = len(secList)
			if *scanSecrets && len(secList) > 0 {
				fmt.Printf("\n󰌆 Secret Scan Findings (%d leaked credentials/secrets detected):\n", len(secList))
				for _, f := range secList {
					relPath, _ := filepath.Rel(absPath, f.FilePath)
					if relPath == "" {
						relPath = f.FilePath
					}
					fmt.Printf("  • [%s] %s:%d -> %s\n", f.Type, relPath, f.LineNumber, f.Match)
				}
			}
		}

		// Handle result
		var model *ui.Model
		if finalModel != nil {
			model = finalModel.(*ui.Model)
			model.SetDone(result, nil, secList, iacList, licList)
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
func handleScanResult(result *types.ScanResult, outputFmt string, finalModel *ui.Model) error {
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
		case "cyclonedx":
			if err := export.CycloneDX(result, os.Stdout); err != nil {
				return err
			}
		case "spdx":
			if err := export.SPDX(result, os.Stdout); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown output format: %s", outputFmt)
		}
	} else {
		// Print summary
		fmt.Printf("\n󰄬 Scan complete: %d dependencies, %d vulnerabilities\n",
			len(result.Dependencies), result.TotalVulns)
		if result.CriticalVulns > 0 {
			fmt.Printf("  󰅚 Critical: %d\n", result.CriticalVulns)
		}
		if result.HighVulns > 0 {
			fmt.Printf("  󰀦 High:     %d\n", result.HighVulns)
		}
		if result.MediumVulns > 0 {
			fmt.Printf("  󰀦 Medium:   %d\n", result.MediumVulns)
		}
		if result.LowVulns > 0 {
			fmt.Printf("  󰌵 Low:      %d\n", result.LowVulns)
		}
	}

	if result.CriticalVulns > 0 || result.HighVulns > 0 {
		os.Exit(1)
	}

	return nil
}

// TUIAdapter adapts the scan.ProgressReporter interface to Bubbletea messages
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

func (t *TUIAdapter) Vulnerability(vuln types.Vulnerability, pkg string, path []string) {
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

func (t *TUIAdapter) Done(result *types.ScanResult) {
	if t.program != nil {
		t.program.Send(ui.DoneMsg{
			Result: result,
		})
	}
}
