package export

import (
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// CSV exports scan results in CSV format.
func CSV(result *models.ScanResult, w io.Writer) error {
	return nil
}
