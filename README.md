# Vigil CLI

Lightweight vulnerability scanner for JavaScript/TypeScript projects.

Analyses dependency trees and reports CVE exposure with context, enriched CVSS scores, and detailed vulnerability information.

## Quick Start

```bash
# Install
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest

# Scan project
cd /path/to/your/node/project
vigil scan .

# View report
vigil report
```

## Features

- **Multi-source CVSS enrichment** - Aggregates scores from NVD, GitHub Security Advisories, and OSV
- **Interactive TUI** - Real-time scanning progress with live vulnerability table
- **Comprehensive CVE data** - Titles, descriptions, publication dates, and dependency paths
- **Multiple report formats**
  - **Table** (default): Compact Trivy-style tabular format with exploit classification
  - **Security**: Production-ready report for AppSec teams with executive summary
  - **Text**: Tree-structured detailed view
  - **CSV/Markdown/JSON**: Export formats for integration
- **Intelligent risk assessment** - Exploit type classification and runtime exploitability analysis
- **Release gate decisions** - Automated recommendations (proceed/mitigate/block)

## Requirements

- Go 1.24+
- Node.js/TypeScript project with lock file (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`)

## Installation

### Option 1: go install (Recommended)

```bash
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

### Option 2: Build from Source

```bash
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli
go build -o vigil ./cmd/vigil
sudo mv vigil /usr/local/bin/
```

See [Installation Guide](documentation/getting-started/installation.md) for details.

## Usage

### Scan Dependencies

```bash
vigil scan .
```

Interactive TUI shows real-time progress and vulnerability table.

### Generate Report

```bash
# Default table format
vigil report

# Security format for AppSec teams
vigil report --format security

# Export to file
vigil report --format csv --export vulns.csv

# Filter by severity
vigil report --filter high
```

### CI/CD Integration

```bash
# Fail build on high/critical vulnerabilities
vigil ci --fail-on high
```

See [Commands Reference](documentation/user-guide/commands.md) for all options.

## Environment Variables

Optional API keys for enhanced data quality:

- `NVD_API_KEY` - NVD API key for authoritative CVE data ([Get key](https://nvd.nist.gov/developers/request-an-api-key))
- `GITHUB_TOKEN` - GitHub token for GHSA data and improved rate limits

## Documentation

- **Getting Started**
  - [Installation](documentation/getting-started/installation.md)
  - [Quick Start](documentation/getting-started/quick-start.md)
  - [Examples](documentation/getting-started/examples.md)
- **User Guide**
  - [Commands Reference](documentation/user-guide/commands.md)
  - [Understanding Reports](documentation/user-guide/reports.md)
  - [Troubleshooting](documentation/user-guide/troubleshooting.md)
- **Architecture**
  - [System Overview](documentation/architecture/overview.md)
  - [Components](documentation/architecture/components.md)
  - [Data Flow](documentation/architecture/data-flow.md)
- **Development**
  - [Setup](documentation/development/setup.md)
  - [Contributing](documentation/development/contributing.md)
  - [Testing](documentation/development/testing.md)

Full documentation index: [documentation/README.md](documentation/README.md)

## Project Structure

```
.
├── cmd/vigil/                  # CLI entry point
├── internal/
│   ├── cli/                    # Command implementations
│   ├── export/                 # Output format encoders
│   ├── github/                 # GitHub Security Advisories client
│   ├── lockfile/               # Lock file parsers and caching
│   ├── nvd/                    # NVD API client
│   ├── osv/                    # OSV API client
│   ├── report/                 # Report generation
│   ├── scan/                   # Scan orchestration
│   ├── types/                  # Core data structures
│   └── ui/                     # Terminal UI (TUI)
├── documentation/
│   ├── getting-started/        # Installation, quick start, examples
│   ├── user-guide/             # Commands, reports, troubleshooting
│   ├── architecture/           # System design and components
│   ├── development/            # Contributing and testing
│   └── adr/                    # Architecture decision records
└── test-project/               # Test fixtures
```

## CVSS Score Sources

Vigil enriches CVSS scores from multiple sources in priority order:

1. **NVD API** (for CVE-* IDs) - Most authoritative source for CVEs
2. **GitHub Security Advisories** (for GHSA-* IDs) - Comprehensive GHSA data
3. **OSV API** - Community-sourced vulnerability data
4. **Derived from severity** - Fallback calculation if unavailable

Ensures every vulnerability has a CVSS score for accurate risk assessment.

## Lock File Support

- `package-lock.json` (npm v1, v2, v3)
- `yarn.lock` (Yarn v1, v2+)
- `pnpm-lock.yaml` (pnpm v5, v6, v9)

## Contributing

See [Contributing Guide](documentation/development/contributing.md).

## Licence

MIT
