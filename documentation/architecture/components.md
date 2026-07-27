# Components

Internal package architecture.

## Package Structure

```
internal/
├── cli/            # Command implementations
├── export/         # Output format encoders
├── github/         # GitHub Security Advisories client
├── lockfile/       # Lock file parsers and caching
├── nvd/            # NVD API client
├── osv/            # OSV API client
├── report/         # Report generation and formatting
├── scan/           # Scan orchestration
├── types/          # Core data structures
└── ui/             # Terminal UI (TUI)
```

## Core Types (`internal/types`)

**Dependency** - Single package with metadata
- Name, Version, Type (production/development)
- Vulnerabilities slice

**Vulnerability** - CVE or GHSA entry
- ID, Summary, Description
- Severity, CVSS score/vector
- Publication dates, references
- Enriched CVE data from NVD

**ScanResult** - Complete scan output
- Project metadata
- Dependencies slice
- Vulnerability counts by severity

**DependencyGraph** - Tree structure for path resolution
- Nodes: package@version with parent/child relationships
- Methods: CalculateDepths(), GetVulnerablePath()

**Severity** - Type-safe severity enum (low/medium/high/critical)
- SeverityMap: string → Severity
- SeverityRank: Severity → int (for comparison)
- Methods: HigherOrEqualThan()

**CVSS utilities** - Score/severity conversions
- DeriveCVSSFromSeverity() - Fallback scoring
- SeverityFromCVSS() - Map score to severity

## CLI Layer (`internal/cli`)

**scan.go** - Scan command
- Detects lock file
- Initialises TUI
- Calls scan orchestrator
- Saves cache

**report.go** - Report command
- Loads cache
- Applies filters
- Delegates to report generators

**ci.go** - CI command
- Loads cache
- Checks thresholds
- Returns exit code

## Scan Orchestration (`internal/scan`)

**orchestrator.go** - Main scanning logic
- Coordinates lock file parsing
- Manages API client calls
- Enriches vulnerability data
- Calculates risk scores
- Reports progress to TUI

## Lock File Parsing (`internal/lockfile`)

**parse.go** - Generic parser interface
- Detects lock file type
- Delegates to specific parser

**parse_pnpm.go** - pnpm-lock.yaml parser
- Handles v5, v6, v9 formats
- Peer dependency resolution
- Builds full dependency graph

**tree.go** - Dependency tree builder
- Converts flat lists to tree structure

**cache.go** - Scan result caching
- SaveCache(), LoadCache()
- HashFile() for cache invalidation

## API Clients

**OSV Client (`internal/osv`)**
- Query() - Single package lookup
- BatchQuery() - Multiple packages
- CalculateRiskScore() - Context-aware scoring

**NVD Client (`internal/nvd`)**
- QueryCVE() - Get CVE details by ID
- Handles v2.0 API format
- Rate limiting (5 or 50 req/30s)

**GitHub Client (`internal/github`)**
- QueryGHSA() - Get advisory details
- GraphQL (with token) or REST (public)
- Rate limiting (60 or 5000 req/hour)

## Report Generation (`internal/report`)

**generator.go** - Format dispatcher

**table.go** - Compact tabular output (Trivy-style)

**text.go** - Tree-structured view

**security.go** - Production AppSec report
- processVulnerabilities() - Enrich entries
- determineReleaseGate() - Go/no-go decision
- analyzeSystemicRisks() - Pattern detection

**filter.go** - Severity filtering

**exploit.go** - Exploit type classification
- Pattern matching on descriptions
- RCE, Injection, Auth Bypass, DoS, etc.

**exploitability.go** - Runtime exploitability assessment
- CVSS vector parsing
- Context-aware analysis

**recommendations.go** - Remediation action suggestions

## Export Formats (`internal/export`)

**csv.go** - CSV encoder

**json.go** - JSON encoder

**markdown.go** - Markdown encoder

## Terminal UI (`internal/ui`)

**scanner.go** - Interactive TUI
- Real-time progress display
- Live vulnerability table
- Bubbletea framework
- Spinner, progress bar, table components

## Dependencies

**External:**
- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/bubbles` - TUI components
- `github.com/charmbracelet/lipgloss` - TUI styling
- `gopkg.in/yaml.v3` - YAML parsing

**Standard library:**
- `encoding/json`, `encoding/csv` - Encoders
- `net/http` - HTTP client
- `crypto/sha256` - Cache hashing
- `time`, `strings`, `io`, `os`, `path/filepath` - Utilities

## Testing Strategy

**Unit tests:**
- Lock file parsers (parse_test.go)
- OSV client (client_test.go)
- Report formatting (text_test.go)
- Export formats (export_test.go)

**Integration tests:**
- End-to-end scan workflows
- API client error handling

**No mocks for API clients** - Real network calls in tests for accuracy

## Next Steps

- [Data Flow](data-flow.md) - Detailed pipeline
- [Overview](overview.md) - System design
- [Development Setup](../development/setup.md) - Contributing
