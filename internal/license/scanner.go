package license

import (
	"strings"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// LicenseCategory classifies open-source licenses by legal risk profile.
type LicenseCategory string

const (
	Permissive LicenseCategory = "Permissive"
	Copyleft   LicenseCategory = "Copyleft"
	Unknown    LicenseCategory = "Unknown"
)

// LicenseFinding represents the identified license of a package.
type LicenseFinding struct {
	PackageName string          `json:"package_name"`
	Version     string          `json:"version"`
	License     string          `json:"license"`
	Category    LicenseCategory `json:"category"`
}

// ClassifyLicense categorizes an SPDX license string into Permissive or Copyleft.
func ClassifyLicense(lic string) LicenseCategory {
	clean := strings.TrimSpace(strings.ToUpper(lic))
	if clean == "" {
		return Unknown
	}

	// Permissive license keywords
	if strings.Contains(clean, "MIT") ||
		strings.Contains(clean, "APACHE") ||
		strings.Contains(clean, "BSD") ||
		strings.Contains(clean, "ISC") ||
		strings.Contains(clean, "UNLICENSE") ||
		strings.Contains(clean, "CC0") ||
		strings.Contains(clean, "WTFPL") {
		return Permissive
	}

	// Copyleft / Restrictive license keywords
	if strings.Contains(clean, "GPL") ||
		strings.Contains(clean, "AGPL") ||
		strings.Contains(clean, "LGPL") ||
		strings.Contains(clean, "MPL") ||
		strings.Contains(clean, "EUPL") ||
		strings.Contains(clean, "CDDL") ||
		strings.Contains(clean, "EPL") {
		return Copyleft
	}

	return Unknown
}

// AnalyzeGraphLicenses iterates over dependency graph nodes and categorizes their licenses.
func AnalyzeGraphLicenses(graph *types.DependencyGraph, licenseMap map[string]string) []LicenseFinding {
	var findings []LicenseFinding

	if graph == nil {
		return findings
	}

	for _, node := range graph.Nodes {
		key := node.Name + "@" + node.Version
		lic := "Unknown"
		if val, ok := licenseMap[key]; ok && val != "" {
			lic = val
		}

		cat := ClassifyLicense(lic)
		findings = append(findings, LicenseFinding{
			PackageName: node.Name,
			Version:     node.Version,
			License:     lic,
			Category:    cat,
		})
	}

	return findings
}
