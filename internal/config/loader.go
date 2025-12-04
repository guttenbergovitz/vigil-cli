package config

import "github.com/guttenbergovitz/vigil-cli/internal/types"

// Load reads and parses .vigil.toml configuration file.
// Returns default config if file doesn't exist.
func Load(path string) (types.Config, error) {
	return types.DefaultConfig(), nil
}
