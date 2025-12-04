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
4. For production dependencies, query OSV API
5. Calculate risk score per CVE
6. Output results

**Exit codes:**
- `0`: Scan completed, no high-risk issues
- `1`: Scan completed, high-risk issues found
- `2`: Scan failed (missing lock file, API error, etc.)

### `vigil report`

Generate report from last scan. Requires `.vigil.cache` from previous scan.

**Flags:**
- `--format <format>`: Output format: `text`, `csv`, `markdown` (default: `text`)
- `--export <file>`: Write to file (optional)
- `--filter <level>`: Show only vulns at or above level: `low`, `medium`, `high`, `critical`

**Output (text):**
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

## OSV API Integration

Query https://api.osv.dev/v1/query for each unique package+version.

**Request format:**
```json
{
  "package": {
    "purl": "pkg:npm/express@4.18.0"
  }
}
```

**Response fields used:**
- `vulns[].id`: CVE ID
- `vulns[].summary`: Brief description
- `vulns[].severity`: CVSS severity
- `vulns[].affected[].versions`: Affected versions
- `vulns[].references`: URLs

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
- **Risk Score**: 45
- **Summary**: XSS vulnerability in template handling
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
