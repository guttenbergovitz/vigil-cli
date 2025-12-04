package report

import (
	"io"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Generator creates reports from scan results.
type Generator struct {
	result *types.ScanResult
}

// New creates a new report generator with scan results.
func New(result *types.ScanResult) *Generator {
	return &Generator{
		result: result,
	}
}

// GenerateText produces human-readable text report.
func (g *Generator) GenerateText(w io.Writer) error {
	return nil
}

// GenerateCSV produces CSV report.
func (g *Generator) GenerateCSV(w io.Writer) error {
	return nil
}

// GenerateMarkdown produces Markdown report.
func (g *Generator) GenerateMarkdown(w io.Writer) error {
	return nil
}
