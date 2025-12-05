# Vigil CLI

Lightweight vulnerability scanner for JavaScript/TypeScript projects. Analyzes dependency trees and reports CVE exposure with context, enriched CVSS scores, and detailed vulnerability information.

## Quick Start

```bash
vigil scan <path>
vigil report
```

## Features

- **Multi-source CVSS enrichment**: Automatically fetches CVSS scores from NVD, GitHub Security Advisories, and OSV
- **Interactive TUI**: Real-time scanning progress with live vulnerability table
- **Comprehensive CVE data**: Includes titles, descriptions, publication dates, and dependency paths
- **Multiple report formats**:
  - **Table** (default): Compact Trivy-style tabular format with exploit classification
  - **Security**: Production-ready report for AppSec teams with executive summary, risk analysis, and release recommendations
  - **Text**: Tree-structured detailed view
  - **CSV/Markdown/JSON**: Export formats for integration
- **Intelligent risk assessment**: Exploit type classification, runtime exploitability analysis, and recommended actions
- **Release gate decisions**: Automated recommendations (proceed/mitigate/block) based on findings

## Environment Variables

- `NVD_API_KEY` (optional): NVD API key for enhanced CVE data and CVSS scores. Get one at https://nvd.nist.gov/developers/request-an-api-key
- `GITHUB_TOKEN` (optional): GitHub token for GitHub Security Advisories API access (improves rate limits)

## Structure

```
.
├── cmd/               # CLI entry points
├── internal/          # Private application code
│   ├── cli/           # CLI commands and flags
│   ├── config/        # Configuration handling
│   ├── export/        # CSV, Markdown export
│   ├── github/        # GitHub Security Advisories integration
│   ├── lockfile/      # Dependency tree analysis & lock file parsing
│   ├── nvd/           # NVD API integration
│   ├── osv/           # OSV API integration
│   ├── report/        # Reporting logic
│   ├── scan/          # Core scanning orchestration
│   ├── types/         # Domain data structures
│   └── ui/            # Terminal UI (TUI) components
├── documentation/     # All docs
│   ├── adr/           # Architecture decisions
│   ├── spec/          # Technical specification
│   ├── guides/        # Developer guidelines
│   └── miss/          # Temporary notes
└── tests/             # Integration tests
```

## Building

```bash
go build -o vigil ./cmd/vigil
```

## Requirements

- Go 1.25+
- No external binary dependencies

## CVSS Score Sources

Vigil enriches CVSS scores from multiple sources in priority order:

1. **NVD API** (for CVE-* IDs): Most authoritative source for CVEs
2. **GitHub Security Advisories** (for GHSA-* IDs): Comprehensive data for GitHub advisories
3. **OSV API**: Includes CVSS from cvssv3, cvssv2, and database_specific fields
4. **Derived from severity**: Fallback calculation if no CVSS available

This ensures every vulnerability has a CVSS score for accurate risk assessment.
