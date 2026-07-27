package lockfile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// pythonPackage holds metadata parsed from Python TOML/JSON lock files.
type pythonPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Category     string            `json:"category"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]string `json:"dependencies"`
	DepNames     []string          `json:"dep_names"`
}

// ParseUVLock parses uv.lock TOML format into Dependencies.
func ParseUVLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseUVLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse uv.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		if pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// ParseUVLockGraph parses uv.lock and builds a DependencyGraph with PyPI ecosystem metadata.
func ParseUVLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseUVLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse uv.lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemPyPI

	// First pass: Add all package nodes
	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		depType := types.Production
		if pkg.Dev {
			depType = types.Development
		}
		graph.AddNode(name, pkg.Version, depType, false)
	}

	// Second pass: Add edges for dependencies
	for _, pkg := range pkgs {
		parentKey := strings.ToLower(pkg.Name) + "@" + pkg.Version
		for _, depName := range pkg.DepNames {
			depNameLower := strings.ToLower(depName)
			// Find installed version in graph
			for childKey, childNode := range graph.Nodes {
				if childNode.Name == depNameLower {
					graph.AddEdge(parentKey, childKey)
					break
				}
			}
		}
	}

	// Identify root nodes (nodes without parents)
	childKeys := make(map[string]bool)
	for _, node := range graph.Nodes {
		for _, child := range node.Children {
			childKeys[child] = true
		}
	}

	for key, node := range graph.Nodes {
		if !childKeys[key] {
			node.Direct = true
			graph.Root = append(graph.Root, key)
		}
	}

	graph.CalculateDepths()
	return graph, nil
}

// parseUVLockPackages parses TOML content of uv.lock line by line.
func parseUVLockPackages(r io.Reader) ([]pythonPackage, error) {
	scanner := bufio.NewScanner(r)
	var pkgs []pythonPackage
	var current *pythonPackage
	inDeps := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			if current != nil {
				pkgs = append(pkgs, *current)
			}
			current = &pythonPackage{}
			inDeps = false
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "dependencies = [") {
			inDeps = true
			continue
		}

		if inDeps {
			if line == "]" {
				inDeps = false
				continue
			}
			// Extract dependency name from `{ name = "foo" }` or `"foo"`
			if idx := strings.Index(line, "name = \""); idx >= 0 {
				rest := line[idx+len("name = \""):]
				if endIdx := strings.Index(rest, "\""); endIdx >= 0 {
					current.DepNames = append(current.DepNames, rest[:endIdx])
				}
			} else if strings.HasPrefix(line, "\"") {
				rest := line[1:]
				if endIdx := strings.Index(rest, "\""); endIdx >= 0 {
					current.DepNames = append(current.DepNames, rest[:endIdx])
				}
			}
			continue
		}

		if strings.HasPrefix(line, "name = \"") {
			current.Name = extractStringValue(line)
		} else if strings.HasPrefix(line, "version = \"") {
			current.Version = extractStringValue(line)
		} else if line == "dev = true" {
			current.Dev = true
		}
	}

	if current != nil {
		pkgs = append(pkgs, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// ParsePoetryLock parses poetry.lock TOML format into Dependencies.
func ParsePoetryLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parsePoetryLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		if pkg.Category == "dev" || pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// parsePoetryLockPackages parses TOML content of poetry.lock line by line.
func parsePoetryLockPackages(r io.Reader) ([]pythonPackage, error) {
	scanner := bufio.NewScanner(r)
	var pkgs []pythonPackage
	var current *pythonPackage
	inDepsSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			if current != nil {
				pkgs = append(pkgs, *current)
			}
			current = &pythonPackage{Dependencies: make(map[string]string)}
			inDepsSection = false
			continue
		}

		if current == nil {
			continue
		}

		if line == "[package.dependencies]" {
			inDepsSection = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inDepsSection = false
		}

		if inDepsSection {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				depName := strings.TrimSpace(parts[0])
				current.DepNames = append(current.DepNames, depName)
			}
			continue
		}

		if strings.HasPrefix(line, "name = \"") {
			current.Name = extractStringValue(line)
		} else if strings.HasPrefix(line, "version = \"") {
			current.Version = extractStringValue(line)
		} else if strings.HasPrefix(line, "category = \"") {
			current.Category = extractStringValue(line)
		}
	}

	if current != nil {
		pkgs = append(pkgs, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// ParsePipfileLock parses Pipfile.lock JSON format into Dependencies.
func ParsePipfileLock(r io.Reader) (*Dependencies, error) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	cleanVersion := func(v string) string {
		v = strings.TrimPrefix(v, "==")
		v = strings.TrimPrefix(v, "=")
		return strings.TrimSpace(v)
	}

	for pkgName, pkg := range lock.Default {
		deps.Production[strings.ToLower(pkgName)] = cleanVersion(pkg.Version)
	}
	for pkgName, pkg := range lock.Develop {
		deps.Development[strings.ToLower(pkgName)] = cleanVersion(pkg.Version)
	}

	return deps, nil
}

var reqSpecRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)(?:[=><~!]=?([a-zA-Z0-9_\-\.\+]+))?`)

// ParseRequirementsTxt parses requirements.txt format into Dependencies.
func ParseRequirementsTxt(r io.Reader) (*Dependencies, error) {
	scanner := bufio.NewScanner(r)
	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments or options (e.g. ; python_version... or --hash...)
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, " --"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		matches := reqSpecRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			pkgName := strings.ToLower(matches[1])
			pkgVer := ""
			if len(matches) >= 3 {
				pkgVer = matches[2]
			}
			if pkgName != "" {
				deps.Production[pkgName] = pkgVer
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse requirements.txt: %w", err)
	}

	return deps, nil
}

// Helper to extract string between double quotes e.g. name = "foo" -> foo
func extractStringValue(line string) string {
	idx := strings.Index(line, "\"")
	if idx < 0 {
		return ""
	}
	rest := line[idx+1:]
	endIdx := strings.Index(rest, "\"")
	if endIdx < 0 {
		return ""
	}
	return rest[:endIdx]
}
