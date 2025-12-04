# ADR 005: Multi-Source CVSS Enrichment

## Status
Accepted

## Context

CVSS scores are critical for risk assessment, but different sources provide different levels of detail:
- OSV API may not always include CVSS scores
- NVD API has authoritative CVSS data for CVE-* IDs but requires API key
- GitHub Security Advisories have CVSS for GHSA-* IDs
- Some vulnerabilities only have severity levels without CVSS scores

## Decision

Implement multi-source CVSS enrichment with fallback chain:
1. NVD API (for CVE-* IDs) - most authoritative
2. GitHub Security Advisories (for GHSA-* IDs)
3. OSV API (cvssv3, cvssv2, database_specific fields)
4. Derived from severity level (last resort)

## Rationale

1. **Completeness**: Ensures every vulnerability has a CVSS score for consistent risk assessment
2. **Accuracy**: NVD is the authoritative source for CVE CVSS scores
3. **Coverage**: GitHub Security Advisories provide CVSS for many npm vulnerabilities
4. **Fallback**: Derived scores ensure no vulnerability is missing a score
5. **User experience**: Users can optionally provide API keys for enhanced data

## Implementation

### NVD API Integration

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Requires: `NVD_API_KEY` environment variable (optional but recommended)
- Queries: CVE-* IDs extracted from OSV references
- Returns: CVSS v3.1/v3.0/v2 scores, severity, descriptions, titles

### GitHub Security Advisories Integration

- Endpoints:
  - GraphQL: `https://api.github.com/graphql` (with token)
  - REST: `https://api.github.com/advisories/{ghsa_id}` (public)
- Requires: `GITHUB_TOKEN` environment variable (optional, improves rate limits)
- Queries: GHSA-* IDs from OSV
- Returns: CVSS scores, vectors, descriptions

### OSV CVSS Extraction

- Checks multiple fields:
  - `cvssv3.score` and `cvssv3.baseScore`
  - `cvssv2.score`
  - `database_specific.cvss_score` and `database_specific.cvss3_score`

### Severity-Based Fallback

If no CVSS score is found, derive from severity:
- Critical → 9.5
- High → 7.5
- Medium → 5.0
- Low → 2.5
- Unknown → 5.0

## Consequences

- **Pros:**
  - Comprehensive CVSS coverage
  - Accurate risk assessment
  - Better user experience with detailed vulnerability data
  - Optional API keys don't block functionality

- **Cons:**
  - Additional API calls may slow scanning
  - Rate limiting considerations for NVD/GitHub APIs
  - More complex codebase with multiple API integrations

## Alternatives Considered

- **Single source (OSV only)**: Simpler but incomplete CVSS coverage
- **NVD only**: Requires CVE ID extraction, misses GHSA-* vulnerabilities
- **No fallback**: Leaves vulnerabilities without CVSS scores

