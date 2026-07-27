# Quick Start

Get scanning in 5 minutes.

## 1. Install Vigil

```bash
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

Verify:

```bash
vigil version
```

## 2. Navigate to Your Project

```bash
cd /path/to/your/node/project
```

Project must contain one of:
- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `pnpm-lock.yaml` (pnpm)

## 3. Run First Scan

```bash
vigil scan .
```

Interactive TUI displays real-time progress:

```
 ● Vigil Scanning...
████████████████████░░░░░░░░░░░░░░░░░░░░ 45% (127/283)
Scanning: express@4.18.2
⏱  Elapsed: 23s
🚨 Vulnerabilities found: 12

📋 Vulnerabilities Found:
Severity │ Package          │ CVE ID            │ CVSS │ Title
────────┼──────────────────┼───────────────────┼──────┼─────────────────────
High    │ semver@7.3.5     │ CVE-2022-25883    │ 7.5  │ Regular expression DoS
Medium  │ minimatch@3.0.4  │ CVE-2022-3517     │ 5.3  │ ReDoS vulnerability
```

## 4. View Detailed Report

After scan completes:

```bash
vigil report
```

Default table format shows:

```
Library          │ Vuln ID           │ Severity │ Exploit Type  │ Fix Available
─────────────────┼───────────────────┼──────────┼───────────────┼───────────────
semver@7.3.5     │ CVE-2022-25883    │ HIGH     │ DoS           │ 7.5.2

SUMMARY
Total: 12  │  🔴 CRITICAL: 0  │  🟠 HIGH: 2  │  🟡 MEDIUM: 8  │  🔵 LOW: 2

✅ Release can proceed
  • No CRITICAL findings
  • 2 HIGH findings in dev dependencies only
```

## 5. Export Results

Save for CI/CD or sharing:

```bash
# CSV for spreadsheets
vigil report --format csv --export vulns.csv

# Markdown for documentation
vigil report --format markdown --export security-report.md

# JSON for automation
vigil report --format json --export results.json

# Production AppSec report
vigil report --format security --export appsec-review.txt
```

## 6. Filter by Severity

Show only critical/high issues:

```bash
vigil report --filter high
```

## 7. CI/CD Integration

Fail builds on critical/high vulnerabilities:

```bash
vigil ci --fail-on high
```

Exit code 0 if pass, 1 if fail.

## Common Workflows

### Development Workflow

```bash
# Scan before committing
vigil scan .

# Check if safe to merge
vigil report --filter high
```

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Scan dependencies
  run: |
    go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
    vigil scan .
    vigil ci --fail-on high
```

### Security Review

```bash
# Generate full AppSec report
vigil scan .
vigil report --format security --export security-review.txt

# Share with team
cat security-review.txt
```

## Understanding Output

### Severity Levels

- **CRITICAL** (CVSS ≥9.0): Immediate action required
- **HIGH** (CVSS 7.0-8.9): Fix in next release
- **MEDIUM** (CVSS 4.0-6.9): Plan remediation
- **LOW** (CVSS 0.1-3.9): Monitor, fix when convenient

### Exploit Types

- **RCE**: Remote code execution
- **Injection**: SQL, XSS, command injection
- **Auth Bypass**: Authentication/authorisation flaws
- **DoS**: Denial of service
- **Data Leak**: Information disclosure
- **Logic Error**: Business logic flaws

### Release Gate Recommendations

- **✅ Proceed**: No blockers, safe to release
- **⚠️ Allowed with mitigations**: Deploy with monitoring/WAF rules
- **❌ Block**: Critical issues require fixes first

## Next Steps

- [Examples](examples.md) - More use cases
- [Commands Reference](../user-guide/commands.md) - Full CLI options
- [Reports](../user-guide/reports.md) - Understanding all output formats
- [Troubleshooting](../user-guide/troubleshooting.md) - Common issues

## Tips

**Speed up scans:**
- Skip dev dependencies: `vigil scan . --skip-devdeps`
- Set `NVD_API_KEY` for faster NVD queries (50 req/30s vs 5 req/30s)

**Reduce noise:**
- Filter low severity: `vigil report --filter medium`
- Focus on production: `vigil scan . --skip-devdeps`

**Share results:**
- Markdown format integrates with GitHub/GitLab wikis
- CSV imports into Jira/Linear for tracking
- Security format provides executive summary for stakeholders
