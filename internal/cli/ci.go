package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// CI executes the ci command
func CI(args []string) error {
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
	result, err := lockfile.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	// Determine fail threshold
	severityMap := map[string]types.Severity{
		"low":      types.Low,
		"medium":   types.Medium,
		"high":     types.High,
		"critical": types.Critical,
	}

	minSev, ok := severityMap[*failOn]
	if !ok {
		return fmt.Errorf("invalid fail-on level: %s", *failOn)
	}

	severityOrder := map[types.Severity]int{
		types.Low:      1,
		types.Medium:   2,
		types.High:     3,
		types.Critical: 4,
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
