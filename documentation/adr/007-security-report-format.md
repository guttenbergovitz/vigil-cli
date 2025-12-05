# ADR 007: Security Report Format

**Status:** Accepted  
**Date:** 2025-12-05  
**Decision Makers:** Development Team

## Context

Vigil CLI needed a production-ready security report format suitable for:
- SOC (Security Operations Center) review
- Change Advisory Board (CAB) presentations
- Incident pre-assessment
- Release gate decisions

The existing tree-structured text format was insufficient for operational security decision-making, lacking:
- Executive summary with risk quantification
- Exploit type classification
- Runtime exploitability assessment
- Actionable recommendations
- Release gate guidance

## Decision

We implemented three complementary report formats:

### 1. Table Format (Default)
- **Purpose**: Quick, scannable overview for developers
- **Inspiration**: Trivy's compact tabular layout
- **Columns**: Library, Vuln ID, Severity, Exploit Type, Exploitability, Fix Available, Recommended Action
- **Summary**: Total findings by severity + release gate

### 2. Security Format
- **Purpose**: Comprehensive AppSec analysis
- **Sections**:
  1. Executive Risk Summary (findings count, production-exploitable, blockers)
  2. Detailed Vulnerability Entries (grouped by severity: CRITICAL→HIGH→MEDIUM→LOW)
  3. Systemic Risk Indicators (repeated vulns, hot clusters, critical layer impacts)
  4. Release Gate Recommendation (✅/⚠️/❌ with justification)

### 3. Text Format (Legacy)
- **Purpose**: Tree-structured detailed view
- **Retained**: For backward compatibility and detailed investigation

## Key Features

### Exploit Type Classification
Vulnerabilities classified into:
- RCE (Remote Code Execution)
- Injection (SQL, XSS, Command, etc.)
- Auth Bypass
- DoS (Denial of Service)
- Data Leak
- Logic Error
- Other

### Runtime Exploitability Assessment
Three levels:
- `yes`: Direct exploit possible (e.g., network-accessible RCE)
- `no`: Requires unlikely conditions
- `conditional`: Depends on configuration/usage

### Recommended Actions
- Immediate hotfix (CRITICAL in production)
- Upgrade in next release (HIGH/MEDIUM in production)
- Infra mitigation required (no code fix available)
- Monitoring only (dev-only or LOW)
- Risk acceptance candidate (LOW with low exploitability)

### Release Gate Logic
- **Block (❌)**: CRITICAL in production OR 3+ HIGH in production
- **Allow with mitigations (⚠️)**: HIGH/MEDIUM manageable with workarounds
- **Proceed (✅)**: Only LOW or dev-only findings

## Consequences

### Positive
- Actionable intelligence for security teams
- Clear release decisions
- Reduced mean time to remediation (MTTR)
- Professional format for audit/compliance
- Multiple formats for different audiences (dev vs AppSec)

### Negative
- Increased code complexity (3 formatters instead of 1)
- More maintenance surface
- Fix status detection not yet automated (placeholder)

### Neutral
- Breaking change: `table` is now default (users can opt into `text` with `--format=text`)

## Implementation

- `internal/report/table.go`: Compact table format
- `internal/report/security.go`: Full AppSec report
- `internal/report/exploit.go`: Exploit classification logic
- `internal/report/exploitability.go`: Exploitability assessment
- `internal/report/recommendations.go`: Action determination

## Alternatives Considered

1. **Single format with flags**: Too complex, hard to maintain
2. **External templates**: Over-engineered for current needs
3. **Markdown-only**: Not suitable for terminal viewing

## References

- Trivy report format: https://github.com/aquasecurity/trivy
- NIST CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
