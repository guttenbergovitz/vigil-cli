package types

import "time"

// Ecosystem represents a package manager ecosystem supported by Vigil.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemGo        Ecosystem = "Go"
	EcosystemCargo     Ecosystem = "Cargo"
	EcosystemPackagist Ecosystem = "Packagist"
)

// Dependency represents a single package and its metadata.
type Dependency struct {
	Name            string
	Version         string
	Ecosystem       Ecosystem      // Package manager ecosystem (npm, PyPI, Go, Cargo, etc.)
	Type            DependencyType // production or development
	ReleasedAt      *time.Time     // Package release date (for temporal filtering)
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
	SecretCount      int
}
