package export

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// JSON exports scan results in JSON format.
func JSON(result *models.ScanResult, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}
