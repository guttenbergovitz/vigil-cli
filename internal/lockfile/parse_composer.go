package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type composerLockStruct struct {
	Packages []struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Require map[string]string `json:"require"`
	} `json:"packages"`
	PackagesDev []struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Require map[string]string `json:"require"`
	} `json:"packages-dev"`
}

// ParseComposerLock parses PHP composer.lock JSON format into Dependencies.
func ParseComposerLock(r io.Reader) (*Dependencies, error) {
	var lock composerLockStruct
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	cleanVersion := func(v string) string {
		return strings.TrimPrefix(v, "v")
	}

	for _, pkg := range lock.Packages {
		if pkg.Name != "" && pkg.Version != "" {
			deps.Production[strings.ToLower(pkg.Name)] = cleanVersion(pkg.Version)
		}
	}
	for _, pkg := range lock.PackagesDev {
		if pkg.Name != "" && pkg.Version != "" {
			deps.Development[strings.ToLower(pkg.Name)] = cleanVersion(pkg.Version)
		}
	}

	return deps, nil
}

// ParseComposerLockGraph parses PHP composer.lock and builds a DependencyGraph with Packagist ecosystem metadata.
func ParseComposerLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	var lock composerLockStruct
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemPackagist

	cleanVersion := func(v string) string {
		return strings.TrimPrefix(v, "v")
	}

	// First pass: Add all nodes (prod and dev)
	for _, pkg := range lock.Packages {
		name := strings.ToLower(pkg.Name)
		ver := cleanVersion(pkg.Version)
		graph.AddNode(name, ver, types.Production, false)
	}
	for _, pkg := range lock.PackagesDev {
		name := strings.ToLower(pkg.Name)
		ver := cleanVersion(pkg.Version)
		graph.AddNode(name, ver, types.Development, false)
	}

	// Helper to add edges from require map
	addEdges := func(pkgName, pkgVersion string, require map[string]string) {
		parentKey := strings.ToLower(pkgName) + "@" + cleanVersion(pkgVersion)
		for childName := range require {
			childNameLower := strings.ToLower(childName)
			// Ignore php or ext-* language requirement constraints
			if childNameLower == "php" || strings.HasPrefix(childNameLower, "ext-") {
				continue
			}
			// Match child package in graph
			for childKey, childNode := range graph.Nodes {
				if childNode.Name == childNameLower {
					graph.AddEdge(parentKey, childKey)
					break
				}
			}
		}
	}

	// Second pass: Add edges
	for _, pkg := range lock.Packages {
		addEdges(pkg.Name, pkg.Version, pkg.Require)
	}
	for _, pkg := range lock.PackagesDev {
		addEdges(pkg.Name, pkg.Version, pkg.Require)
	}

	// Identify root nodes
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
