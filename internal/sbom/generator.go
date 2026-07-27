package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// GenerateCycloneDX generates a CycloneDX v1.5 JSON SBOM.
func GenerateCycloneDX(result *types.ScanResult, graph *types.DependencyGraph, w io.Writer) error {
	projectName := filepath.Base(result.ProjectPath)
	if projectName == "." || projectName == "/" || projectName == "" {
		projectName = "root-project"
	}

	cycloneDX := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"serialNumber": fmt.Sprintf("urn:uuid:vigil-%d", time.Now().UnixNano()),
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]interface{}{
				{
					"vendor":  "Vigil Security",
					"name":    "vigil-cli",
					"version": "1.1.0",
				},
			},
			"component": map[string]interface{}{
				"name": projectName,
				"type": "application",
			},
		},
		"components": buildCycloneDXComponents(graph, result),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cycloneDX); err != nil {
		return fmt.Errorf("encode CycloneDX JSON: %w", err)
	}

	return nil
}

// GenerateSPDX generates an SPDX v2.3 JSON SBOM.
func GenerateSPDX(result *types.ScanResult, graph *types.DependencyGraph, w io.Writer) error {
	projectName := filepath.Base(result.ProjectPath)
	if projectName == "." || projectName == "/" || projectName == "" {
		projectName = "root-project"
	}

	spdx := map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              projectName,
		"documentNamespace": fmt.Sprintf("https://spdx.org/spdxdocs/vigil-%s-%d", projectName, time.Now().UnixNano()),
		"creationInfo": map[string]interface{}{
			"created": time.Now().UTC().Format(time.RFC3339),
			"creators": []string{
				"Tool: vigil-cli-1.1.0",
			},
		},
		"packages": buildSPDXPackages(graph, result),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(spdx); err != nil {
		return fmt.Errorf("encode SPDX JSON: %w", err)
	}

	return nil
}

func buildCycloneDXComponents(graph *types.DependencyGraph, result *types.ScanResult) []map[string]interface{} {
	var components []map[string]interface{}

	lockFile := ""
	if result != nil {
		lockFile = result.LockFile
	}

	if graph != nil && len(graph.Nodes) > 0 {
		for _, node := range graph.Nodes {
			components = append(components, map[string]interface{}{
				"type":    "library",
				"name":    node.Name,
				"version": node.Version,
				"purl":    buildPurl(node.Name, node.Version, node.Ecosystem, lockFile),
			})
		}
	} else if result != nil {
		for _, dep := range result.Dependencies {
			components = append(components, map[string]interface{}{
				"type":    "library",
				"name":    dep.Name,
				"version": dep.Version,
				"purl":    buildPurl(dep.Name, dep.Version, dep.Ecosystem, lockFile),
			})
		}
	}

	return components
}

func buildSPDXPackages(graph *types.DependencyGraph, result *types.ScanResult) []map[string]interface{} {
	var packages []map[string]interface{}

	lockFile := ""
	if result != nil {
		lockFile = result.LockFile
	}

	if graph != nil && len(graph.Nodes) > 0 {
		for _, node := range graph.Nodes {
			spdxID := fmt.Sprintf("SPDXRef-Package-%s-%s", sanitizeSPDXID(node.Name), sanitizeSPDXID(node.Version))
			packages = append(packages, map[string]interface{}{
				"name":        node.Name,
				"SPDXID":      spdxID,
				"versionInfo": node.Version,
				"externalRefs": []map[string]interface{}{
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType":     "purl",
						"referenceLocator":  buildPurl(node.Name, node.Version, node.Ecosystem, lockFile),
					},
				},
			})
		}
	} else if result != nil {
		for _, dep := range result.Dependencies {
			spdxID := fmt.Sprintf("SPDXRef-Package-%s-%s", sanitizeSPDXID(dep.Name), sanitizeSPDXID(dep.Version))
			packages = append(packages, map[string]interface{}{
				"name":        dep.Name,
				"SPDXID":      spdxID,
				"versionInfo": dep.Version,
				"externalRefs": []map[string]interface{}{
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType":     "purl",
						"referenceLocator":  buildPurl(dep.Name, dep.Version, dep.Ecosystem, lockFile),
					},
				},
			})
		}
	}

	return packages
}

func buildPurl(pkg, version string, eco types.Ecosystem, lockFile string) string {
	if eco == "" && lockFile != "" {
		lf := strings.ToLower(lockFile)
		switch {
		case strings.Contains(lf, "uv.lock"), strings.Contains(lf, "poetry.lock"), strings.Contains(lf, "pipfile.lock"), strings.Contains(lf, "requirements.txt"):
			eco = types.EcosystemPyPI
		case strings.Contains(lf, "cargo.lock"):
			eco = types.EcosystemCargo
		case strings.Contains(lf, "composer.lock"):
			eco = types.EcosystemPackagist
		case strings.Contains(lf, "go.mod"):
			eco = types.EcosystemGo
		default:
			eco = types.EcosystemNPM
		}
	}

	purlType := "npm"
	switch eco {
	case types.EcosystemPyPI:
		purlType = "pypi"
	case types.EcosystemGo:
		purlType = "golang"
	case types.EcosystemCargo:
		purlType = "cargo"
	case types.EcosystemPackagist:
		purlType = "composer"
	default:
		purlType = "npm"
	}

	cleanPkg := pkg
	if strings.HasPrefix(pkg, "@") {
		cleanPkg = strings.ReplaceAll(pkg, "@", "%40")
	}

	return fmt.Sprintf("pkg:%s/%s@%s", purlType, cleanPkg, version)
}

func sanitizeSPDXID(s string) string {
	s = strings.ReplaceAll(s, "@", "")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return s
}
