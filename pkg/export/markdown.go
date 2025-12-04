package export

import (
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// Markdown exports scan results in Markdown format.
func Markdown(result *models.ScanResult, w io.Writer) error {
	return nil
}
