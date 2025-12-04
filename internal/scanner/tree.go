package scanner

import (
	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// BuildDependencyTree converts flat dependency maps into structured Dependency list.
func BuildDependencyTree(deps *Dependencies) ([]models.Dependency, error) {
	var result []models.Dependency

	// Add production dependencies
	for name, version := range deps.Production {
		result = append(result, models.Dependency{
			Name:            name,
			Version:         version,
			Type:            models.Production,
			Vulnerabilities: []models.Vulnerability{},
		})
	}

	// Add development dependencies
	for name, version := range deps.Development {
		result = append(result, models.Dependency{
			Name:            name,
			Version:         version,
			Type:            models.Development,
			Vulnerabilities: []models.Vulnerability{},
		})
	}

	return result, nil
}
