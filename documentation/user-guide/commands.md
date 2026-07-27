# Commands Reference

Complete CLI command documentation.

## vigil scan

Scan project for vulnerabilities.

### Synopsis

```bash
vigil scan [path] [flags]
```

### Arguments

- `path` - Project directory or git repository URL to scan (default: current directory)

### Flags

- `--skip-devdeps` - Skip development dependencies
- `--output <format>` - Save results (json, csv, markdown)

### Behaviour

1. Locate lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
2. Parse dependency tree (direct + transitive)
3. Tag dependencies as production/development
4. Query OSV API for each unique package@version
5. Enrich CVSS scores from NVD/GitHub/OSV
6. Extract CVE IDs and query NVD for details
7. Query GitHub Security Advisories for GHSA-* IDs
8. Calculate risk scores
9. Display real-time progress in interactive TUI
10. Cache results to `.vigil.cache`

### Exit Codes

- `0` - Scan completed successfully
- `1` - Scan completed, vulnerabilities found
- `2` - Scan failed (missing lock file, API error)

### Examples

```bash
# Scan current directory
vigil scan .

# Scan specific project
vigil scan /path/to/project

# Scan remote repository (public)
vigil scan https://github.com/user/repo

# Scan remote repository (private, requires GITHUB_TOKEN)
export GITHUB_TOKEN=ghp_xxxxx
vigil scan https://github.com/user/private-repo

# Scan via SSH
vigil scan git@github.com:user/repo.git

# Scan and export
vigil scan . --output json

# Production dependencies only
vigil scan . --skip-devdeps
```

### Remote Scanning

Vigil can scan repositories directly without manual cloning:

**Supported protocols:**
- `https://` - HTTPS URLs (GitHub, Bitbucket, GitLab)
- `http://` - HTTP URLs
- `git@` - SSH URLs
- `ssh://` - SSH URLs

**Authentication:**
- Public repos: No authentication needed
- Private GitHub repos: Set `GITHUB_TOKEN` environment variable
- SSH repos: Uses system SSH keys from `~/.ssh`

**Behaviour:**
1. Clone repository to temp directory (`--depth 1`)
2. Scan lockfile from cloned repo
3. Automatic cleanup after scan completes

**Notes:**
- Only the lockfile is needed (no `node_modules` required)
- Shallow clone used for speed (`--depth 1`)
- Temp directory cleaned up even on error
- For HTTPS URLs with `GITHUB_TOKEN`, token is injected into clone URL

### Rate Limiting

API calls are rate-limited to respect service limits:

**OSV API:**
- No authentication required
- 10ms delay between requests
- No explicit rate limit

**NVD API:**
- Without key: 5 requests/30s (6s delay)
- With `NVD_API_KEY`: 50 requests/30s (600ms delay)
- Set environment variable to improve speed

**GitHub Security Advisories:**
- Without token: 60 requests/hour
- With `GITHUB_TOKEN`: 5000 requests/hour
- GraphQL endpoint used when token available

### Lock File Support

**npm (package-lock.json):**
- v1, v2, v3 formats supported
- Flat and nested structures

**Yarn (yarn.lock):**
- Yarn v1 (classic)
- Yarn v2+ (Berry)

**pnpm (pnpm-lock.yaml):**
- v5, v6, v9 formats
- Peer dependency resolution
- Workspace support

### Output

Interactive TUI shows:
- Real-time scan progress
- Current package being scanned
- Live vulnerability count
- Dynamic vulnerability table
- Elapsed time

Press `q` to quit during scan.

---

## vigil report

Generate report from cached scan results.

### Synopsis

```bash
vigil report [flags]
```

### Flags

- `--format <format>` - Output format (default: `table`)
  - `table` - Compact tabular format with exploit classification
  - `text` - Tree-structured detailed view
  - `security` - Production AppSec report
  - `csv` - CSV export
  - `markdown` - Markdown export
  - `json` - JSON export
- `--export <file>` - Write to file instead of stdout
- `--filter <level>` - Show only vulnerabilities at or above level

### Filter Levels

- `low` - All vulnerabilities (CVSS 0.1+)
- `medium` - Medium and above (CVSS 4.0+)
- `high` - High and critical (CVSS 7.0+)
- `critical` - Critical only (CVSS 9.0+)

### Formats

#### Table (Default)

Compact Trivy-style output:

```
Library          │ Vuln ID           │ Severity │ Exploit Type  │ Exploitability │ Recommended Action
─────────────────┼───────────────────┼──────────┼───────────────┼────────────────┼────────────────────
semver@7.3.5     │ CVE-2022-25883    │ HIGH     │ DoS           │ yes            │ Immediate hotfix
ip@2.0.1         │ CVE-2024-29415    │ HIGH     │ SSRF          │ conditional    │ Upgrade next release

SUMMARY
Total: 12  │  🔴 CRITICAL: 0  │  🟠 HIGH: 2  │  🟡 MEDIUM: 8  │  🔵 LOW: 2

✅ Release can proceed
```

#### Text

Tree-structured view:

```
CRITICAL (0)

HIGH (2)
├── semver@7.3.5: CVE-2022-25883
│   └── Regular expression denial of service
│   └── Path: express@4.18.2 → semver@7.3.5
│
└── ip@2.0.1: CVE-2024-29415
    └── SSRF vulnerability in IP validation
    └── Path: request@2.88.2 → ip@2.0.1
```

#### Security

Production-ready AppSec report:

```
═══════════════════════════════════════════════════════════════════
                   SECURITY VULNERABILITY REPORT
═══════════════════════════════════════════════════════════════════

Project:      /path/to/project
Scan Date:    2025-12-04T10:30:00Z
Dependencies: 283

═══════════════════════════════════════════════════════════════════
1. EXECUTIVE RISK SUMMARY
═══════════════════════════════════════════════════════════════════

Total Findings: 12
  CRITICAL: 0
  HIGH:     2
  MEDIUM:   8
  LOW:      2

Production-exploitable: 1
Development-only: 11

═══════════════════════════════════════════════════════════════════
2. VULNERABILITY DETAILS
═══════════════════════════════════════════════════════════════════

HIGH SEVERITY (2)
-----------------

CVE-2022-25883: semver@7.3.5
  Environment:          production
  CVSS Score:           7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
  Exploit Type:         DoS
  Runtime Exploitability: yes
  Recommended Action:   Immediate hotfix
  Fix Available:        7.5.2
  Dependency Path:      express@4.18.2 → semver@7.3.5

  Technical Summary:
  Regular expression denial of service in semver parsing...

[... detailed entries for all vulnerabilities ...]

═══════════════════════════════════════════════════════════════════
3. SYSTEMIC RISK SIGNALS
═══════════════════════════════════════════════════════════════════

• No repeated vulnerabilities across dependencies
• No critical dependency clusters identified
• No core infrastructure layer impacts

═══════════════════════════════════════════════════════════════════
4. RELEASE GATE RECOMMENDATION
═══════════════════════════════════════════════════════════════════

✅ Release can proceed

Rationale:
  • No CRITICAL findings blocking release
  • 2 HIGH findings are in development dependencies only
  • Production surface has acceptable risk profile
  • Recommend addressing HIGH findings in next sprint
```

#### CSV

```csv
package,version,type,cve_id,summary,severity,risk_score
semver,7.3.5,production,CVE-2022-25883,ReDoS vulnerability,high,75
ip,2.0.1,production,CVE-2024-29415,SSRF in IP validation,high,72
```

#### Markdown

```markdown
# Vulnerability Report

## High (2)

### CVE-2022-25883

- **Package**: semver@7.3.5
- **Severity**: High
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Description**: Regular expression denial of service...
```

#### JSON

Full scan results in JSON format for automation.

### Examples

```bash
# Default table format
vigil report

# Security format for AppSec team
vigil report --format security

# Export CSV for Jira
vigil report --format csv --export vulns.csv

# Filter critical only
vigil report --filter critical

# Markdown for documentation
vigil report --format markdown --export SECURITY.md
```

### Requirements

Requires `.vigil.cache` from previous `vigil scan` run.

---

## vigil ci

CI/CD integration command.

### Synopsis

```bash
vigil ci [flags]
```

### Flags

- `--fail-on <level>` - Fail if vulnerabilities at or above level exist (default: `high`)
  - `low`, `medium`, `high`, `critical`
- `--fail-on-cvss <score>` - Fail if any CVSS score ≥ threshold (0.0-10.0)
- `--format <format>` - Output format (text, json, csv, markdown)

### Exit Codes

- `0` - No vulnerabilities above threshold
- `1` - Vulnerabilities found above threshold
- `2` - Error (missing cache, invalid flags)

### Examples

```bash
# Fail on high or critical
vigil ci --fail-on high

# Fail on CVSS ≥ 8.0
vigil ci --fail-on-cvss 8.0

# Combined severity and CVSS check
vigil ci --fail-on high --fail-on-cvss 7.5

# Output JSON for processing
vigil ci --fail-on critical --format json
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Security gate
  run: vigil ci --fail-on high

# GitLab CI
script:
  - vigil ci --fail-on critical

# Jenkins
sh 'vigil ci --fail-on high'
```

---

## vigil version

Display version information.

### Synopsis

```bash
vigil version
```

### Output

```
vigil version 0.1.0
```

---

## Global Behaviour

### Environment Variables

- `NVD_API_KEY` - NVD API key for enhanced CVE data
- `GITHUB_TOKEN` - GitHub token for GHSA data and improved rate limits

### Cache Location

Scan results cached in `.vigil.cache` (JSON format) in scanned directory.

### Error Handling

**Missing lock file:**
```
error: No lock file found. Please run this in a Node.js/TypeScript project with
package-lock.json, yarn.lock, or pnpm-lock.yaml
```

**API unreachable:**
```
error: OSV API error: connection timeout
```

**Invalid cache:**
```
error: load cache: invalid JSON format
```

### Logging

Minimal output to stderr. TUI output to stdout (scan command only).

## Next Steps

- [Reports](reports.md) - Detailed report format documentation
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Examples](../getting-started/examples.md) - Practical use cases
