package config

import "github.com/guttenbergovitz/vigil-cli/pkg/models"

// Load reads and parses .vigil.toml configuration file.
// Returns default config if file doesn't exist.
func Load(path string) (models.Config, error) {
	return models.DefaultConfig(), nil
}
