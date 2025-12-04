package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
	"gopkg.in/yaml.v3"
)

// ParsePnpmLock parses pnpm-lock.yaml format and builds dependency graph.
func ParsePnpmLock(r io.Reader) (*Dependencies, error) {
	var lockFile struct {
		Packages map[string]struct {
			Dev          bool              `yaml:"dev"`
			Dependencies map[string]string `yaml:"dependencies"`
		} `yaml:"packages"`
		ImportersRoot struct {
			Dependencies    map[string]string `yaml:"dependencies"`
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
		// Strip peer dependencies suffix if present (e.g. "/pkg@1.0.0(peer@2.0.0)")
		if idx := strings.Index(pkgPath, "("); idx > 0 {
			pkgPath = pkgPath[:idx]
		}

		// Strip leading slash from name if present
		pkgPath = strings.TrimPrefix(pkgPath, "/")

		// Determine where to split name and version
		var splitIdx int
		if strings.HasPrefix(pkgPath, "@") {
			// Scoped package: @scope/name@version
			// Find second @
			firstAt := strings.Index(pkgPath[1:], "@")
			if firstAt == -1 {
				continue
			}
			splitIdx = firstAt + 1
		} else {
			// Regular package: name@version
			// Find first @
			splitIdx = strings.Index(pkgPath, "@")
		}

		if splitIdx <= 0 {
			continue
		}

		name := pkgPath[:splitIdx]
		rest := pkgPath[splitIdx+1:]
		var version string

		// Handle pnpm v9 peer dependency separator "_"
		// Format: version_peer1@ver_peer2@ver
		// We want just the version
		if idx := strings.Index(rest, "_"); idx > 0 {
			version = rest[:idx]
		} else {
			version = rest
		}

		// Handle legacy path suffix if present (e.g. name@version/subpath)
		if idx := strings.Index(version, "/"); idx > 0 {
			version = version[:idx]
		}

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
func ParsePnpmLockGraph(r io.Reader) (*types.DependencyGraph, error) {
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

	graph := types.NewDependencyGraph()

	// Parse package path format: "name@version" or "@scope/name@version" or "name/subpath@version"
	// Parse package path format: "name@version" or "@scope/name@version" or "name/subpath@version"
	// Parse package path format: "name@version" or "@scope/name@version" or "name/subpath@version"
	extractNameVersion := func(pkgPath string) (name, version string) {
		// Strip peer dependencies suffix if present (e.g. "/pkg@1.0.0(peer@2.0.0)")
		if idx := strings.Index(pkgPath, "("); idx > 0 {
			pkgPath = pkgPath[:idx]
		}

		// Strip leading slash from name if present
		pkgPath = strings.TrimPrefix(pkgPath, "/")

		// Determine where to split name and version
		var splitIdx int
		if strings.HasPrefix(pkgPath, "@") {
			// Scoped package: @scope/name@version
			// Find second @
			firstAt := strings.Index(pkgPath[1:], "@")
			if firstAt == -1 {
				return "", ""
			}
			splitIdx = firstAt + 1
		} else {
			// Regular package: name@version
			// Find first @
			splitIdx = strings.Index(pkgPath, "@")
		}

		if splitIdx <= 0 {
			return "", ""
		}

		name = pkgPath[:splitIdx]
		rest := pkgPath[splitIdx+1:]

		// Handle pnpm v9 peer dependency separator "_"
		// Format: version_peer1@ver_peer2@ver
		// We want just the version
		if idx := strings.Index(rest, "_"); idx > 0 {
			version = rest[:idx]
		} else {
			version = rest
		}

		// Handle legacy path suffix if present (e.g. name@version/subpath)
		// Though usually pnpm keys don't have both _ and / in this way, but let's be safe
		if idx := strings.Index(version, "/"); idx > 0 {
			version = version[:idx]
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

		typ := types.Production
		if pkg.Dev {
			typ = types.Development
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
	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	scanner := bufio.NewScanner(r)
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check if this is a package header (not indented)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Parse package header: "package-name@version:" or "\"package-name@npm:version\":"
			header := strings.TrimSuffix(trimmed, ":")
			header = strings.Trim(header, "\"")

			// Handle both v1 (@version) and v2+ (@npm:version)
			if strings.Contains(header, "@npm:") {
				// Yarn v2+ format: "package-name@npm:version"
				parts := strings.Split(header, "@npm:")
				if len(parts) == 2 {
					currentPackage = parts[0]
					// Version will be extracted from the "version:" field below
				}
			} else if lastAt := strings.LastIndex(header, "@"); lastAt > 0 {
				// Yarn v1 format: "package-name@version-spec"
				// The version spec might be "~1.20.0" or "^2.0.0", extract package name only
				currentPackage = header[:lastAt]
				// Version will be extracted from the "version:" field below
			}
		} else if strings.HasPrefix(trimmed, "version:") && currentPackage != "" {
			// Extract the resolved version
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"")
				if version != "" {
					deps.Production[currentPackage] = version
					currentPackage = "" // Reset for next package
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse yarn lock: %w", err)
	}

	return deps, nil
}
