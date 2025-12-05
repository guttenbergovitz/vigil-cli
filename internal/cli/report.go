package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/lockfile"
	"github.com/guttenbergovitz/vigil-cli/internal/report"
)

// Report executes the report command
func Report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	format := fs.String("format", "text", "Output format (text, security, csv, markdown, json)")
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
	result, err := lockfile.LoadCache(cachePath)
	if err != nil {
		return fmt.Errorf("load cache: %w", err)
	}

	// Filter results if requested
	if *filterLevel != "" {
		result = report.FilterByLevel(result, *filterLevel)
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
		return report.Text(result, out)
	case "security":
		return report.Security(result, out)
	case "csv":
		return export.CSV(result, out)
	case "markdown":
		return export.Markdown(result, out)
	case "json":
		return export.JSON(result, out)
	default:
		return fmt.Errorf("unknown format: %s (available: text, security, csv, markdown, json)", *format)
	}
}
