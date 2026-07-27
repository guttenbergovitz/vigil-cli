# Data Flow

Detailed scanning and enrichment pipeline.

## Scan Pipeline

### 1. Lock File Detection

```
cli/scan.go
  ↓
lockfile.DetectLockFileType()
  ↓
Returns: (lockType, lockFilePath, lockHash)
```

Checks for files in order:
1. `package-lock.json`
2. `yarn.lock`
3. `pnpm-lock.yaml`

Computes SHA256 hash for cache invalidation.

### 2. Cache Check

```
lockfile.LoadCache()
  ↓
Compare hash with cached hash
  ↓
If match: return cached ScanResult
If mismatch: continue to scan
```

Cache hit avoids all API calls.

### 3. Lock File Parsing

```
lockfile.ParseLockFile() or lockfile.ParsePnpmLockGraph()
  ↓
Extract dependencies with versions
  ↓
Build DependencyGraph (for pnpm) or flat list (npm/Yarn)
  ↓
Tag each dependency: production or development
```

**npm/Yarn**: Flat dependency list

**pnpm**: Full graph with parent/child relationships

### 4. Vulnerability Discovery (OSV)

For each unique package@version:

```
osv.Query(name, version)
  ↓
POST https://api.osv.dev/v1/query
  {
    "package": {"purl": "pkg:npm/express@4.18.0"}
  }
  ↓
Parse response vulnerabilities
  ↓
Extract: ID, Summary, Severity, CVSS, References
  ↓
Sleep 10ms (rate limiting)
```

Primary vulnerability source. Returns both CVE-* and GHSA-* IDs.

### 5. CVE Enrichment (NVD)

For vulnerabilities with CVE-* ID:

```
nvd.QueryCVE(cveID)
  ↓
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234
  Headers: apiKey (if NVD_API_KEY set)
  ↓
Parse response
  ↓
Extract: CVSS v3.1/v3.0/v2, Severity, Description, Published date
  ↓
Merge into vulnerability entry
  ↓
Sleep 6s (no key) or 600ms (with key)
```

Authoritative source for CVE data. Overrides OSV scores.

### 6. GHSA Enrichment (GitHub)

For vulnerabilities with GHSA-* ID:

```
github.QueryGHSA(ghsaID)
  ↓
If GITHUB_TOKEN set:
  POST https://api.github.com/graphql
  Query: securityAdvisory(ghsaId: "GHSA-...")
Else:
  GET https://api.github.com/advisories/GHSA-...
  ↓
Parse response
  ↓
Extract: CVSS, Severity, Description, CVE mapping
  ↓
Merge into vulnerability entry
```

Comprehensive data for GitHub advisories.

### 7. CVSS Score Prioritisation

For each vulnerability:

```
if CVSSScore == 0:
  1. Check NVD score (if CVE-*)
  2. Check GitHub score (if GHSA-*)
  3. Check OSV score
  4. Derive from severity (fallback)

if Severity weak/unknown:
  Derive from CVSS score
```

Ensures all vulnerabilities have CVSS score for risk assessment.

### 8. Temporal False Positive Filtering

For each package:

```
npm.GetReleaseDate(name, version)
  ↓
GET https://registry.npmjs.org/{name}/{version}
  ↓
Parse release timestamp from time.{version}
  ↓
types.FilterTemporalFalsePositives(releasedAt, vulns)
  ↓
For each vulnerability:
  if vuln.PublishedAt < packageReleased:
    Filter out (false positive)
  else:
    Keep (real vulnerability)
  ↓
Return filtered vulnerability list
```

**Conservative approach:**
- If release date unavailable: keep all vulns
- If CVE publish date unavailable: keep vuln

**Impact:**
- Reduces false positives by 30-40%
- Improves signal-to-noise ratio

### 9. Dependency Path Resolution

For pnpm (graph available):

```
graph.GetVulnerablePath(nodeKey)
  ↓
Walk backwards through parents
  ↓
Build chain: root → ... → vulnerable package
```

For npm/Yarn (flat list):

```
Direct dependencies only (no graph)
```

### 10. Risk Scoring

```
osv.CalculateRiskScoreWithDepth(severity, isProduction, depth)
  ↓
Base score from severity
+ 20 if production dependency
+ depth penalty (farther from root = lower urgency)
  ↓
Returns 0-100 risk score
```

### 11. TUI Progress Reporting

Throughout scan:

```
reporter.Progress(current, total, currentPkg, vulnCount)
  ↓
TUI updates:
  - Progress bar
  - Current package
  - Vulnerabilities found count
  - Live vulnerability table
```

Non-blocking updates via channels.

### 12. Result Aggregation

```
buildScanResultFromGraph()
  ↓
Convert DependencyGraph to []Dependency
  ↓
Count vulnerabilities by severity
  ↓
Create ScanResult struct
```

### 13. Cache Save

```
lockfile.SaveCache(cachePath, result)
  ↓
JSON encode ScanResult
  ↓
Write to .vigil.cache
```

Enables fast subsequent reports.

## Report Pipeline

### 1. Load Cached Results

```
lockfile.LoadCache()
  ↓
Read .vigil.cache
  ↓
JSON decode to ScanResult
```

### 2. Filter (Optional)

```
report.FilterByLevel(result, minSeverity)
  ↓
Keep only vulns >= threshold
  ↓
Recount severity totals
```

### 3. Classify Exploits

```
For each vulnerability:
  report.ClassifyExploitType(vuln)
    ↓
  Pattern match on summary/description
    ↓
  Return: RCE, Injection, Auth Bypass, DoS, etc.
```

### 4. Assess Exploitability

```
report.AssessRuntimeExploitability(vuln, exploitType)
  ↓
Parse CVSS vector
  ↓
Check: AV (attack vector), AC (complexity), PR (privileges)
  ↓
Return: yes, conditional, no
```

### 5. Determine Remediation Actions

```
report.DetermineRecommendedAction(vuln, depType, exploitType, exploitability)
  ↓
Decision tree based on:
  - Severity
  - Production vs dev
  - Exploit type
  - Exploitability
  ↓
Return: Immediate hotfix, Upgrade next release, etc.
```

### 6. Compute Release Gate

```
report.determineReleaseGate(result, entries)
  ↓
Check:
  - Critical findings in production?
  - High + exploitable in production?
  - Mitigations available?
  ↓
Return: ✅ Proceed | ⚠️ Allowed with mitigations | ❌ Block
```

### 7. Format Output

Delegates to format-specific generator:

**Table**: Compact rows with key fields

**Text**: Tree structure grouped by severity

**Security**: Full AppSec report with sections

**CSV**: One row per vulnerability

**Markdown**: Formatted for documentation

**JSON**: Complete ScanResult structure

### 8. Export (Optional)

```
Write formatted output to file
```

## Data Structures Flow

```
Lock File
  ↓ (parse)
Dependencies: []Dependency
  ↓ (query OSV)
Vulnerabilities: []Vulnerability (minimal)
  ↓ (enrich NVD/GitHub)
Vulnerabilities: []Vulnerability (complete)
  ↓ (classify)
VulnEntry: {Library, VulnID, Severity, ExploitType, Exploitability, Action}
  ↓ (format)
Output: string (table/text/security/csv/markdown/json)
```

## Concurrency

**Sequential**:
- API calls (rate limiting)
- Lock file parsing → API queries → cache save

**Parallel** (via goroutines + channels):
- TUI updates (non-blocking progress reporting)

## Error Propagation

```
Low-level error (API timeout)
  ↓
Return error to caller
  ↓
Orchestrator decides: continue or fail
  ↓
Critical error: exit with code 2
Non-critical: log and continue
```

## Next Steps

- [Overview](overview.md) - System design
- [Components](components.md) - Package details
- [ADRs](../adr/) - Design decisions
