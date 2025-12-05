# Vigil CLI Specification

## Overview

`vigil` is a command-line tool for scanning JavaScript/TypeScript projects and reporting vulnerability exposure.

## Commands

### `vigil scan <path>`

Scans a project directory and analyzes dependencies.

**Arguments:**
- `<path>`: Directory to scan (required)

**Flags:**
- `--config <file>`: Load custom `.vigil.toml` (optional)
- `--skip-devdeps`: Ignore dev dependencies (optional)
- `--output <format>`: Save results in format: `json`, `csv`, `markdown` (optional)

**Behavior:**
1. Locate `package.json` and lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
2. Parse lock file into transitive dependency tree
3. Tag each dependency: `production` or `development`
4. For each dependency, query OSV API for vulnerabilities
5. For each vulnerability, enrich CVSS score from NVD/GitHub/OSV sources
6. Extract CVE IDs from references and query NVD API for detailed data
7. Query GitHub Security Advisories for GHSA-* IDs
8. Calculate risk score per CVE
9. Display results in interactive TUI with real-time progress
10. Save results to `.vigil.cache`

**Exit codes:**
- `0`: Scan completed, no high-risk issues
- `1`: Scan completed, high-risk issues found
- `2`: Scan failed (missing lock file, API error, etc.)

### `vigil report`

Generate report from last scan. Requires `.vigil.cache` from previous scan.

**Flags:**
- `--format <format>`: Output format (default: `table`)
  - `table`: Compact tabular format with exploit classification (Trivy-style)
  - `text`: Tree-structured detailed view
  - `security`: Production-ready AppSec report with executive summary, risk analysis, and release gate recommendations
  - `csv`: CSV export
  - `markdown`: Markdown export
  - `json`: JSON export
- `--export <file>`: Write to file (optional)
- `--filter <level>`: Show only vulns at or above level: `low`, `medium`, `high`, `critical`

**Output (table - default):**
```
Library          │ Vuln ID           │ Severity │ Exploit Type  │ Exploitability │ Fix Available │ Recommended Action
─────────────────┼───────────────────┼──────────┼───────────────┼────────────────┼───────────────┼────────────────────
astro@5.13.3     │ CVE-2025-64764    │ HIGH     │ XSS/Injection │ yes            │ 5.14.0        │ Immediate hotfix
ip@2.0.1         │ CVE-2024-29415    │ HIGH     │ SSRF          │ conditional    │ 2.0.2         │ Upgrade next release

SUMMARY
Total Findings: 18  │  🔴 CRITICAL: 0  │  🟠 HIGH: 2  │  🟡 MEDIUM: 9  │  🔵 LOW: 7

✅ Release can proceed
  • No CRITICAL or HIGH production vulnerabilities
  • 7 LOW findings represent acceptable background risk
```

**Output (security format):**
Full AppSec report including:
1. Executive Risk Summary (total findings, production-exploitable count, release blockers)
2. Detailed vulnerability entries grouped by severity
3. Systemic risk indicators (repeated vulnerabilities, hot clusters, critical layer impacts)
4. Release gate recommendation (✅/⚠️/❌) with technical justification

**Output (text format):**
```
Project: /path/to/project
Scanned: 2025-12-04T10:30:00Z

CRITICAL (1)
├── package-a@1.0.0: CVE-2024-1234
│   └── Risk: Package is in production, exploit exists
│
MEDIUM (3)
├── package-b@2.1.0: CVE-2024-5678
├── package-c@0.5.0: CVE-2024-9999
```

### `vigil ci --fail-on <level>`

Exit with code 1 if vulnerabilities at or above `<level>` exist.

**Flags:**
- `--fail-on <level>`: Minimum severity to fail: `low`, `medium`, `high`, `critical`
- `--format <format>`: Optional format output

**Use case:** CI/CD gate in GitHub Actions, GitLab CI, etc.

## Dependency Analysis

### Lock File Support

- `package-lock.json` (npm v6+)
- `yarn.lock` (Yarn v1, v2+)
- `pnpm-lock.yaml`

### Transitive Dependencies

Each dependency in the tree is resolved to its full version chain.

```
project
├── express@4.18.0
│   ├── body-parser@1.20.0
│   │   └── bytes@3.1.0
│   └── send@0.18.0
```

### Production vs Development

- **Production**: Included in final bundle/runtime. Queries OSV API.
- **Development**: Not included in runtime. Scanned but not alerting by default.

## Vulnerability Data Sources

### OSV API Integration

Primary source for vulnerability discovery. Query https://api.osv.dev/v1/query for each unique package+version.

**Request format:**
```json
{
  "package": {
    "purl": "pkg:npm/express@4.18.0"
  }
}
```

**Response fields used:**
- `vulns[].id`: CVE ID or GHSA ID
- `vulns[].summary`: Brief description
- `vulns[].severity`: Severity level
- `vulns[].cvssv3`: CVSS v3 score and vector
- `vulns[].cvssv2`: CVSS v2 score
- `vulns[].database_specific`: Additional CVSS data
- `vulns[].affected[].versions`: Affected versions
- `vulns[].references`: URLs (used to extract CVE IDs)

### NVD API Integration

For CVE-* IDs, Vigil queries NVD API v2.0 to enrich data:
- CVSS v3.1/v3.0/v2 scores
- Authoritative severity levels
- Detailed descriptions and titles
- Publication dates

**Environment variable:** `NVD_API_KEY` (optional but recommended)

**Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

### GitHub Security Advisories

For GHSA-* IDs, Vigil queries GitHub Security Advisories API:
- CVSS scores and vectors
- Detailed descriptions
- CVE ID mapping

**Environment variable:** `GITHUB_TOKEN` (optional, improves rate limits)

**Endpoints:**
- GraphQL: `https://api.github.com/graphql` (with token)
- REST: `https://api.github.com/advisories/{ghsa_id}` (public)

### CVSS Score Priority

CVSS scores are enriched from multiple sources in priority order:
1. NVD API (for CVE-*)
2. GitHub Security Advisories (for GHSA-*)
3. OSV API (cvssv3, cvssv2, database_specific)
4. Derived from severity level (fallback)

## Risk Scoring

Risk score: 0-100

```
base = CVSS severity score (0-100)

modifiers:
+ 20 if package in production
+ 15 if exploit publicly available
+ 10 if popular package (>1M downloads/week)
- 10 if patchable within current version range
- 20 if issue in optional dependency
```

## Caching

Scan results cached in `.vigil.cache` (JSON):

```json
{
  "version": 1,
  "project_path": "/path",
  "scanned_at": "2025-12-04T10:30:00Z",
  "lock_file": "package-lock.json",
  "dependencies": [
    {
      "name": "express",
      "version": "4.18.0",
      "type": "production",
      "vulnerabilities": [
        {
          "id": "CVE-2024-1234",
          "severity": "medium",
          "risk_score": 45
        }
      ]
    }
  ]
}
```

## Configuration File (.vigil.toml)

Optional project-level configuration:

```toml
[scan]
skip_devdeps = false

[osv]
# Leave empty to use default endpoint
url = ""
timeout = 10  # seconds

[export]
default_format = "markdown"
```

## Output Formats

### Text (default)

Human-readable, organized by severity.

### CSV

One vulnerability per row:

```csv
package,version,type,cve_id,summary,severity,risk_score
express,4.18.0,production,CVE-2024-1234,XSS vulnerability,medium,45
```

### Markdown

Formatted for documentation/reports:

```markdown
# Vulnerability Report

## Critical (1)

### CVE-2024-1234
- **Package**: express@4.18.0
- **Severity**: Medium
- **CVSS Score**: 7.5/10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **CVE ID**: CVE-2024-1234
- **Title**: XSS vulnerability in template handling
- **Description**: Full description from NVD
- **Risk Score**: 45
- **Published**: 2024-01-15
- **Dependency Path**: express@4.18.0 → body-parser@1.20.0
```

## Error Handling

**Missing lock file:**
- Exit 2, message: "No supported lock file found (package-lock.json, yarn.lock, pnpm-lock.yaml)"

**OSV API unreachable:**
- Exit 2, message: "OSV API error: {error}"

**Invalid TOML config:**
- Exit 2, message: "Invalid .vigil.toml: {error}"

**Empty project:**
- Exit 0, no dependencies found
