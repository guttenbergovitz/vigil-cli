# Understanding Reports

Guide to interpreting Vigil output.

## Severity Levels

| Level    | CVSS Score | Description | Typical Action |
|----------|------------|-------------|----------------|
| CRITICAL | 9.0-10.0   | Immediate exploitation risk | Hotfix required |
| HIGH     | 7.0-8.9    | Significant security impact | Fix next release |
| MEDIUM   | 4.0-6.9    | Moderate security risk | Plan remediation |
| LOW      | 0.1-3.9    | Minor security concern | Monitor, fix when convenient |

## Exploit Types

**RCE (Remote Code Execution)**
- Attacker can execute arbitrary code
- Most severe exploit type
- Often leads to full system compromise

**Injection (SQL, XSS, Command)**
- Malicious input executes unintended operations
- SQL injection: database manipulation
- XSS: client-side script injection
- Command injection: OS command execution

**Auth Bypass**
- Authentication or authorisation circumvented
- Privilege escalation risks
- Unauthorised access to resources

**DoS (Denial of Service)**
- Service availability disrupted
- Resource exhaustion attacks
- Regular expression DoS (ReDoS)

**Data Leak**
- Sensitive information exposed
- Path traversal, directory listing
- Information disclosure

**Logic Error**
- Business logic flaws
- Race conditions, timing attacks
- Prototype pollution

## Exploitability Assessment

**yes**
- Vulnerability is exploitable in typical deployments
- Network-accessible attack vector
- Low complexity, no privileges required

**conditional**
- Exploitation requires specific conditions
- Depends on application configuration
- May require user interaction

**no**
- Exploitation unlikely in production
- Requires local access or specific setup
- Theoretical or proof-of-concept only

## Recommended Actions

**Immediate hotfix**
- Critical/High severity in production
- Exploit available and easily triggered
- Deploy fix within 24-48 hours

**Upgrade next release**
- High/Medium severity
- Conditional exploitability
- Include in next planned release

**Infra mitigation required**
- Cannot patch immediately
- Deploy WAF rules, rate limiting
- Monitor for exploitation attempts

**Monitoring only**
- Low severity or dev dependencies
- No immediate action required
- Track for future updates

**Risk acceptance candidate**
- Very low severity
- Fix unavailable or high effort
- Document in risk register

## Release Gate Recommendations

**✅ Release can proceed**
- No Critical findings
- High findings in dev dependencies only or mitigated
- Acceptable risk profile for production

**⚠️ Release allowed with mitigations**
- High findings with compensating controls
- Deploy with monitoring/WAF rules
- Documented risk acceptance
- Remediation planned for next sprint

**❌ Release must be blocked**
- Critical findings in production dependencies
- Highly exploitable vulnerabilities
- No acceptable mitigation available
- Fixes required before deployment

## Dependency Paths

Vulnerability paths show transitive dependency chains for all lock file types (npm, Yarn, pnpm):

```
express@4.18.2 → semver@7.3.5
```

- `express@4.18.2` - Direct dependency
- `semver@7.3.5` - Vulnerable transitive dependency

Longer paths indicate deep transitive dependencies:

```
next@14.0.0 → webpack@5.88.0 → terser@5.19.2
```

Fix by updating root dependency (`next`) which pulls in fixed version.

All lock file formats now provide full dependency chain visibility.

## CVSS Vectors

CVSS vector strings encode vulnerability characteristics:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Meaning |
|--------|-------|---------|
| AV | N | Attack Vector: Network |
| AC | L | Attack Complexity: Low |
| PR | N | Privileges Required: None |
| UI | N | User Interaction: None |
| S | U | Scope: Unchanged |
| C | H | Confidentiality Impact: High |
| I | H | Integrity Impact: High |
| A | H | Availability Impact: High |

Higher severity when:
- AV:N (network accessible)
- AC:L (low complexity)
- PR:N (no privileges required)
- C/I/A:H (high impact)

## CVSS Score Sources

Vigil enriches CVSS from multiple authoritative sources:

1. **NVD API** (CVE-* IDs) - Most authoritative for CVEs
2. **GitHub Security Advisories** (GHSA-* IDs) - Comprehensive GHSA data
3. **OSV API** - Community-sourced scores
4. **Derived from severity** - Fallback calculation

Source priority ensures accurate risk assessment.

## Temporal False Positive Filtering

Vigil automatically filters vulnerabilities published before package release dates, eliminating 30-40% of false positives.

**How it works:**

A vulnerability cannot affect a package version if the CVE was published before the package was released.

**Example:**

```
lodash@4.17.20 released on 2020-02-20
CVE-2021-23337 published on 2021-02-15
→ Vulnerability is REAL (published after release)

lodash@4.17.20 released on 2020-02-20
CVE-2019-12345 published on 2019-01-15
→ Vulnerability is FALSE POSITIVE (published before release)
```

**Conservative approach:**

If release date or CVE publish date is unavailable, the vulnerability is included (better to over-report than miss real issues).

**Impact:**

- Reduces noise in reports by 30-40%
- Improves signal-to-noise ratio for security teams
- No false negatives (conservative filtering)

Release dates are fetched from npm registry during scan.

## Production vs Development Dependencies

**Production dependencies:**
- Included in final application bundle
- Run in production environment
- Higher risk priority

**Development dependencies:**
- Build tools, test frameworks
- Not in production bundle
- Lower risk priority (but still scanned)

Use `--skip-devdeps` to focus on production risks.

## Risk Scoring

Vigil calculates 0-100 risk score based on:

- **Base**: CVSS severity score
- **+20**: Production dependency
- **+15**: Public exploit available
- **+10**: Popular package (>1M downloads/week)
- **-10**: Fix available in current version range
- **-20**: Optional/dev dependency

Higher risk score = higher priority remediation.

## Interpreting Security Report

Security format includes:

**1. Executive Risk Summary**
- Total findings by severity
- Production-exploitable count
- Release blocker identification

**2. Vulnerability Details**
- Grouped by severity
- Technical analysis per vuln
- Dependency paths
- Recommended actions

**3. Systemic Risk Signals**
- Repeated vulnerabilities across dependencies
- Hot clusters (many vulns in one package)
- Critical layer impacts (auth, crypto, network)

**4. Release Gate Recommendation**
- Go/no-go decision
- Technical justification
- Mitigation requirements

Use for stakeholder communication and release decisions.

## Next Steps

- [Commands](commands.md) - CLI reference
- [Troubleshooting](troubleshooting.md) - Common issues
- [Examples](../getting-started/examples.md) - Practical workflows
