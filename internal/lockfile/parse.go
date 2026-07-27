package lockfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Dependencies holds parsed production and development dependencies.
type Dependencies struct {
	Production  map[string]string
	Development map[string]string
}

// ParseNPMLock parses npm package-lock.json format.
func ParseNPMLock(r io.Reader) (*Dependencies, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse npm lock: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for pkgPath, pkg := range lock.Packages {
		// Skip root package
		if pkgPath == "" || pkg.Version == "" {
			continue
		}

		// Extract package name from path
		// For scoped packages: "node_modules/@scope/name" -> "@scope/name"
		// For regular packages: "node_modules/name" -> "name"
		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
			// Remove any nested node_modules subdirectories (transitive deps)
			// e.g., "node_modules/foo/node_modules/bar" -> "bar"
			if subIdx := strings.Index(name, "/node_modules/"); subIdx >= 0 {
				name = name[subIdx+len("/node_modules/"):]
			}
		}

		if pkg.Dev {
			deps.Development[name] = pkg.Version
		} else {
			deps.Production[name] = pkg.Version
		}
	}

	return deps, nil
}

// ParseNPMLockGraph parses npm package-lock.json and returns full dependency graph.
func ParseNPMLockGraph(r io.Reader) (*types.DependencyGraph, error) {
	var lock struct {
		Packages map[string]struct {
			Version      string            `json:"version"`
			Dev          bool              `json:"dev"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}

	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse npm lock graph: %w", err)
	}

	graph := types.NewDependencyGraph()

	// Extract package name from node_modules path
	extractName := func(pkgPath string) string {
		if pkgPath == "" {
			return ""
		}

		name := pkgPath
		if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
			name = pkgPath[idx+len("node_modules/"):]
			// Remove nested node_modules subdirs
			if subIdx := strings.Index(name, "/node_modules/"); subIdx >= 0 {
				name = name[subIdx+len("/node_modules/"):]
			}
		}
		return name
	}

	// First pass: add all nodes
	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" || pkg.Version == "" {
			continue
		}

		name := extractName(pkgPath)
		if name == "" {
			continue
		}

		typ := types.Production
		if pkg.Dev {
			typ = types.Development
		}

		graph.AddNode(name, pkg.Version, typ, false)
	}

	// Second pass: add edges from dependencies field
	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" {
			continue
		}

		var parentName string
		var parentVersion string

		if pkgPath == "" {
			// Root package - skip as parent
			continue
		}

		parentName = extractName(pkgPath)
		parentVersion = pkg.Version

		if parentName == "" || parentVersion == "" {
			continue
		}

		parentKey := parentName + "@" + parentVersion

		// Add edges to children
		for childName, childVersion := range pkg.Dependencies {
			childKey := childName + "@" + childVersion
			graph.AddEdge(parentKey, childKey)
		}
	}

	// Third pass: identify roots from root package
	if rootPkg, ok := lock.Packages[""]; ok {
		// Root dependencies are in packages[""].dependencies
		// But we need to find their actual installed versions in the graph
		var rootDeps, rootDevDeps map[string]string

		// In npm lock v2+, root dependencies are stored differently
		// We need to re-parse to get the root deps
		// For now, mark packages as root if they're referenced by root
		for childName, childVersion := range rootPkg.Dependencies {
			key := childName + "@" + childVersion
			if node, ok := graph.Nodes[key]; ok {
				node.Direct = true
				graph.Root = append(graph.Root, key)
			}
		}

		// Mark dev deps (need to re-read root package structure)
		_ = rootDeps
		_ = rootDevDeps
	}

	// Alternative: mark nodes as root if they're not children of any other node
	// This is a fallback for when we can't extract root deps cleanly
	childNodes := make(map[string]bool)
	for _, node := range graph.Nodes {
		for _, child := range node.Children {
			childNodes[child] = true
		}
	}

	for key, node := range graph.Nodes {
		if !childNodes[key] && !node.Direct {
			// This node is not a child of anything, likely a root
			node.Direct = true
			graph.Root = append(graph.Root, key)
		}
	}

	graph.CalculateDepths()

	return graph, nil
}

// LockFileType represents the type of lock file.
type LockFileType string

const (
	NPMLock         LockFileType = "npm"
	YarnLock        LockFileType = "yarn"
	PnpmLock        LockFileType = "pnpm"
	UVLock          LockFileType = "uv"
	PoetryLock      LockFileType = "poetry"
	PipfileLock     LockFileType = "pipfile"
	RequirementsTxt LockFileType = "requirements"
	CargoLock       LockFileType = "cargo"
	ComposerLock    LockFileType = "composer"
	GoModLock       LockFileType = "gomod"
)

// Ecosystem maps a lock file type to its target package ecosystem.
func (t LockFileType) Ecosystem() types.Ecosystem {
	switch t {
	case UVLock, PoetryLock, PipfileLock, RequirementsTxt:
		return types.EcosystemPyPI
	case CargoLock:
		return types.EcosystemCargo
	case ComposerLock:
		return types.EcosystemPackagist
	case GoModLock:
		return types.EcosystemGo
	default:
		return types.EcosystemNPM
	}
}

// FindLockFile searches for supported lock files in the given directory in priority order.
// Returns the filename and type of the first found lock file, or error if none found.
func FindLockFile(dir string) (string, LockFileType, error) {
	candidates := []struct {
		name string
		typ  LockFileType
	}{
		{"uv.lock", UVLock},
		{"poetry.lock", PoetryLock},
		{"Pipfile.lock", PipfileLock},
		{"requirements.txt", RequirementsTxt},
		{"package-lock.json", NPMLock},
		{"yarn.lock", YarnLock},
		{"pnpm-lock.yaml", PnpmLock},
		{"Cargo.lock", CargoLock},
		{"composer.lock", ComposerLock},
		{"go.mod", GoModLock},
	}

	for _, candidate := range candidates {
		path := filepath.Join(dir, candidate.name)
		if _, err := os.Stat(path); err == nil {
			return candidate.name, candidate.typ, nil
		}
	}

	return "", "", errors.New("no supported lock file found (uv.lock, poetry.lock, Pipfile.lock, requirements.txt, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, composer.lock, go.mod)")
}

// ParseLockFile dispatches to the correct parser based on lock file type.
func ParseLockFile(r io.Reader, typ LockFileType) (*Dependencies, error) {
	switch typ {
	case NPMLock:
		return ParseNPMLock(r)
	case PnpmLock:
		return ParsePnpmLock(r)
	case YarnLock:
		return ParseYarnLock(r)
	case UVLock:
		return ParseUVLock(r)
	case PoetryLock:
		return ParsePoetryLock(r)
	case PipfileLock:
		return ParsePipfileLock(r)
	case RequirementsTxt:
		return ParseRequirementsTxt(r)
	case CargoLock:
		return ParseCargoLock(r)
	case ComposerLock:
		return ParseComposerLock(r)
	case GoModLock:
		return ParseGoMod(r)
	default:
		return nil, fmt.Errorf("unknown or unsupported lock file type: %s", typ)
	}
}

// ParsePackageJSON extracts name and version from package.json.
func ParsePackageJSON(r io.Reader) (map[string]interface{}, error) {
	var pkg map[string]interface{}

	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	return pkg, nil
}
