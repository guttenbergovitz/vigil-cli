package models

import "time"

// Dependency represents a single npm package and its metadata.
type Dependency struct {
	Name            string
	Version         string
	Type            DependencyType // production or development
	Vulnerabilities []Vulnerability
}

// DependencyType indicates if dependency is used in production or only for development.
type DependencyType string

const (
	Production  DependencyType = "production"
	Development DependencyType = "development"
)

// Vulnerability represents a single CVE or security advisory.
type Vulnerability struct {
	ID           string
	Summary      string
	Description  string    // Full description/details from database
	Severity     Severity
	CVSSScore    float64   // CVSS v3.0+ score (0.0-10.0)
	CVSSVector   string    // CVSS vector string for detailed analysis
	RiskScore    int       // Vigil's computed risk score (0-100)
	References   []string
	PublishedAt  *time.Time
	ModifiedAt   *time.Time
	Sources      []string  // Sources where vulnerability was found (osv, nvd, github, etc)
	// CVE data from MITRE/NVD
	CVEID        string    // CVE-YYYY-*** identifier from MITRE
	CVETitle     string    // Title from NVD/MITRE
	CVEDescription string   // Full description from NVD/MITRE
	CVESeverity  Severity  // Severity from MITRE/NVD
}

// Severity represents CVE severity level.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// ScanResult contains results of a single scan operation.
type ScanResult struct {
	Version          int
	ProjectPath      string
	ScannedAt        time.Time
	LockFile         string
	LockFileHash     string // SHA256 hash for cache invalidation
	Dependencies     []Dependency
	TotalVulns       int
	CriticalVulns    int
	HighVulns        int
	MediumVulns      int
	LowVulns         int
}

// Config represents .vigil.toml configuration.
type Config struct {
	Scan   ScanConfig   `toml:"scan"`
	OSV    OSVConfig    `toml:"osv"`
	Export ExportConfig `toml:"export"`
}

// ScanConfig holds scan-related settings.
type ScanConfig struct {
	SkipDevDeps bool `toml:"skip_devdeps"`
}

// OSVConfig holds OSV API settings.
type OSVConfig struct {
	URL     string `toml:"url"`
	Timeout int    `toml:"timeout"`
}

// ExportConfig holds export-related settings.
type ExportConfig struct {
	DefaultFormat string `toml:"default_format"`
}

// DefaultConfig returns configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Scan: ScanConfig{
			SkipDevDeps: false,
		},
		OSV: OSVConfig{
			URL:     "https://api.osv.dev/v1/query",
			Timeout: 10,
		},
		Export: ExportConfig{
			DefaultFormat: "text",
		},
	}
}
