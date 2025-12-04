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
		// pnpm v5/v9 root dependencies
		Dependencies    map[string]interface{} `yaml:"dependencies"`
		DevDependencies map[string]interface{} `yaml:"devDependencies"`
		// pnpm v6+ importers
		Importers map[string]struct {
			Dependencies    map[string]interface{} `yaml:"dependencies"`
			DevDependencies map[string]interface{} `yaml:"devDependencies"`
		} `yaml:"importers"`
	}

	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lockFile); err != nil {
		return nil, fmt.Errorf("parse pnpm lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()

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

		// Initially assume NOT direct, we will mark roots later
		graph.AddNode(name, version, typ, false)
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
			// childVersion might be a version or a reference
			// In pnpm, it's often just the version, but sometimes it's a reference
			// For simplicity, we assume it matches a node in the graph
			// But we need to find WHICH node matches childName + childVersion

			// Simple matching: look for a node with this name and version
			// This is imperfect because childVersion might be a range or alias
			// But for pnpm lockfile, it's usually resolved version

			childKey := childName + "@" + childVersion
			graph.AddEdge(parentKey, childKey)
		}
	}

	// Identify roots
	// Collect all direct dependencies from root or importers
	roots := make(map[string]string) // name -> version

	// Helper to add roots
	addRoots := func(deps map[string]interface{}) {
		for name, val := range deps {
			var version string

			switch v := val.(type) {
			case string:
				version = v
			case map[string]interface{}:
				// pnpm v6+ format: { "specifier": "^1.0.0", "version": "1.0.0" }
				if ver, ok := v["version"].(string); ok {
					version = ver
				} else if spec, ok := v["specifier"].(string); ok {
					// Fallback to specifier if version missing (unlikely for lockfile)
					version = spec
				}
			}

			if version == "" {
				continue
			}

			// Clean version (strip specifiers if needed)
			// For pnpm, it's usually the version or "link:..."
			if strings.HasPrefix(version, "link:") {
				continue
			}

			// Handle "version(peers)" format in dependencies
			if idx := strings.Index(version, "("); idx > 0 {
				version = version[:idx]
			}

			roots[name] = version
		}
	}

	// Add from root dependencies (v5/v9)
	addRoots(lockFile.Dependencies)
	addRoots(lockFile.DevDependencies)

	// Add from importers (v6+)
	// Usually "." is the root importer
	for _, importer := range lockFile.Importers {
		addRoots(importer.Dependencies)
		addRoots(importer.DevDependencies)
	}

	// Mark root nodes
	for name, version := range roots {
		// Try to find matching node
		// Exact match
		key := name + "@" + version
		if node, ok := graph.Nodes[key]; ok {
			node.Direct = true
			graph.Root = append(graph.Root, key)
			continue
		}

		// If exact match fails (e.g. version mismatch or complex specifier),
		// try to find ANY node with this name (fallback)
		// This is risky but better than missing it
		for nodeKey, node := range graph.Nodes {
			if node.Name == name && node.Version == version {
				node.Direct = true
				graph.Root = append(graph.Root, nodeKey)
				break
			}
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
