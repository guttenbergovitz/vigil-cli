package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type cargoPackage struct {
	Name     string
	Version  string
	DepNames []string
}

// ParseCargoLock parses Rust Cargo.lock TOML format into Dependencies.
func ParseCargoLock(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseCargoLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		if pkg.Name != "" && pkg.Version != "" {
			deps.Production[strings.ToLower(pkg.Name)] = pkg.Version
		}
	}

	return deps, nil
}

// ParseCargoLockGraph parses Rust Cargo.lock and builds a DependencyGraph with Cargo ecosystem metadata.
func ParseCargoLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseCargoLockPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemCargo

	// First pass: Add all crate nodes
	for _, pkg := range pkgs {
		name := strings.ToLower(pkg.Name)
		graph.AddNode(name, pkg.Version, types.Production, false)
	}

	// Second pass: Add dependency edges
	for _, pkg := range pkgs {
		parentKey := strings.ToLower(pkg.Name) + "@" + pkg.Version
		for _, depName := range pkg.DepNames {
			depNameLower := strings.ToLower(depName)
			// Match child crate in graph
			for childKey, childNode := range graph.Nodes {
				if childNode.Name == depNameLower {
					graph.AddEdge(parentKey, childKey)
					break
				}
			}
		}
	}

	// Identify roots (nodes without parents)
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

// parseCargoLockPackages parses TOML content of Cargo.lock line by line.
func parseCargoLockPackages(r io.Reader) ([]cargoPackage, error) {
	scanner := bufio.NewScanner(r)
	var pkgs []cargoPackage
	var current *cargoPackage
	inDeps := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			if current != nil && current.Name != "" {
				pkgs = append(pkgs, *current)
			}
			current = &cargoPackage{}
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
			// Extract dependency string e.g. "bytes" or "bytes 1.0.0"
			cleanLine := strings.Trim(line, "\", ")
			if cleanLine != "" {
				parts := strings.Fields(cleanLine)
				if len(parts) > 0 {
					current.DepNames = append(current.DepNames, parts[0])
				}
			}
			continue
		}

		if strings.HasPrefix(line, "name = \"") {
			current.Name = extractStringValue(line)
		} else if strings.HasPrefix(line, "version = \"") {
			current.Version = extractStringValue(line)
		}
	}

	if current != nil && current.Name != "" {
		pkgs = append(pkgs, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}
