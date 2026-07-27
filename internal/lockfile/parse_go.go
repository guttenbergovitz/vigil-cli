package lockfile

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

type goPackage struct {
	Name       string
	Version    string
	IsIndirect bool
}

// ParseGoMod parses Go go.mod format into Dependencies.
func ParseGoMod(r io.Reader) (*Dependencies, error) {
	pkgs, err := parseGoModPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, pkg := range pkgs {
		if pkg.IsIndirect {
			deps.Development[pkg.Name] = pkg.Version
		} else {
			deps.Production[pkg.Name] = pkg.Version
		}
	}

	return deps, nil
}

// ParseGoModGraph parses Go go.mod and builds a DependencyGraph with Go ecosystem metadata.
func ParseGoModGraph(r io.Reader) (*types.DependencyGraph, error) {
	pkgs, err := parseGoModPackages(r)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod graph: %w", err)
	}

	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemGo

	for _, pkg := range pkgs {
		depType := types.Production
		if pkg.IsIndirect {
			depType = types.Development
		}
		node := graph.AddNode(pkg.Name, pkg.Version, depType, !pkg.IsIndirect)
		if !pkg.IsIndirect {
			graph.Root = append(graph.Root, node.Name+"@"+node.Version)
		}
	}

	graph.CalculateDepths()
	return graph, nil
}

// parseGoModPackages parses go.mod file line by line.
func parseGoModPackages(r io.Reader) ([]goPackage, error) {
	scanner := bufio.NewScanner(r)
	var pkgs []goPackage
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}

		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}

			pkg := parseGoRequireLine(line)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
			continue
		}

		if strings.HasPrefix(line, "require ") {
			reqContent := strings.TrimPrefix(line, "require ")
			pkg := parseGoRequireLine(reqContent)
			if pkg != nil {
				pkgs = append(pkgs, *pkg)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// parseGoRequireLine parses a single require line e.g. "github.com/gin-gonic/gin v1.7.0" or with "// indirect"
func parseGoRequireLine(line string) *goPackage {
	isIndirect := strings.Contains(line, "// indirect")
	// Strip comments
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return &goPackage{
			Name:       parts[0],
			Version:    parts[1],
			IsIndirect: isIndirect,
		}
	}

	return nil
}
