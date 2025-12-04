package scanner

import (
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

// ParsePnpmLock parses pnpm-lock.yaml format and builds dependency graph.
func ParsePnpmLock(r io.Reader) (*Dependencies, error) {
	var lockFile struct {
		Packages map[string]struct {
			Dev          bool     `yaml:"dev"`
			Dependencies map[string]string `yaml:"dependencies"`
		} `yaml:"packages"`
		ImportersRoot struct {
			Dependencies map[string]string `yaml:"dependencies"`
			DevDependencies map[string]string `yaml:"devDependencies"`
		} `yaml:"importers"` // pnpm v6+
	}

	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lockFile); err != nil {
		return nil, fmt.Errorf("parse pnpm lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	// Track all packages
	for pkgPath, pkg := range lockFile.Packages {
		// pnpm format: "package-name@1.0.0" or "package-name@1.0.0/sub/dependency"
		parts := strings.SplitN(pkgPath, "@", 2)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		// Extract version (everything after @ before next / if any)
		versionPart := strings.SplitN(parts[1], "/", 2)
		version := versionPart[0]

		if version == "" {
			continue
		}

		isDev := pkg.Dev

		if isDev {
			deps.Development[name] = version
		} else {
			deps.Production[name] = version
		}
	}

	return deps, nil
}

// ParsePnpmLockGraph parses pnpm-lock.yaml and returns full dependency graph.
func ParsePnpmLockGraph(r io.Reader) (*models.DependencyGraph, error) {
	var lockFile struct {
		Packages map[string]struct {
			Dev          bool              `yaml:"dev"`
			Dependencies map[string]string `yaml:"dependencies"`
		} `yaml:"packages"`
	}

	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lockFile); err != nil {
		return nil, fmt.Errorf("parse pnpm lock graph: %w", err)
	}

	graph := models.NewDependencyGraph()

	// Parse package path format: "name@version" or "@scope/name@version" or "name/subpath@version"
	extractNameVersion := func(pkgPath string) (name, version string) {
		// Find last @ which separates name from version
		lastAtIdx := strings.LastIndex(pkgPath, "@")
		if lastAtIdx <= 0 {
			return "", ""
		}

		// Check if there's a "/" after the last @ (means it's a path after version)
		afterAt := pkgPath[lastAtIdx+1:]
		slashIdx := strings.Index(afterAt, "/")

		if slashIdx >= 0 {
			// Has path after version, extract version before the /
			version = afterAt[:slashIdx]
			name = pkgPath[:lastAtIdx]
		} else {
			// No path, last @ separates name and version
			version = afterAt
			name = pkgPath[:lastAtIdx]
		}

		return name, version
	}

	// First pass: add all nodes
	for pkgPath, pkg := range lockFile.Packages {
		if pkgPath == "" {
			continue
		}

		name, version := extractNameVersion(pkgPath)
		if name == "" || version == "" {
			continue
		}

		typ := models.Production
		if pkg.Dev {
			typ = models.Development
		}

		// Determine if direct (no "/" after version in path)
		isDirect := !strings.Contains(pkgPath[strings.LastIndex(pkgPath, "@")+1+len(version):], "/")

		graph.AddNode(name, version, typ, isDirect)
		if isDirect {
			graph.Root = append(graph.Root, name+"@"+version)
		}
	}

	// Second pass: add edges (dependencies)
	for pkgPath, pkg := range lockFile.Packages {
		if pkgPath == "" {
			continue
		}

		name, version := extractNameVersion(pkgPath)
		if name == "" || version == "" {
			continue
		}

		parentKey := name + "@" + version

		// Add edges to children
		for childName, childVersion := range pkg.Dependencies {
			childKey := childName + "@" + childVersion
			graph.AddEdge(parentKey, childKey)
		}
	}

	graph.CalculateDepths()
	return graph, nil
}

// ParseYarnLock parses yarn.lock format (v1 and v2+).
func ParseYarnLock(r io.Reader) (*Dependencies, error) {
	// Yarn.lock is not YAML but custom format
	// For now, return placeholder - proper implementation needed
	return &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}, fmt.Errorf("yarn.lock parsing not yet implemented")
}
