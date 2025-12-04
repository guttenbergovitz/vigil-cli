package lockfile

import (
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// BuildDependencyTree converts flat dependency maps into structured Dependency list.
func BuildDependencyTree(deps *Dependencies) ([]types.Dependency, error) {
	var result []types.Dependency

	// Add production dependencies
	for name, version := range deps.Production {
		result = append(result, types.Dependency{
			Name:            name,
			Version:         version,
			Type:            types.Production,
			Vulnerabilities: []types.Vulnerability{},
		})
	}

	// Add development dependencies
	for name, version := range deps.Development {
		result = append(result, types.Dependency{
			Name:            name,
			Version:         version,
			Type:            types.Development,
			Vulnerabilities: []types.Vulnerability{},
		})
	}

	return result, nil
}
