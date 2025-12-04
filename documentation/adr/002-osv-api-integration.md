# ADR 002: OSV API for Vulnerability Data

## Status
Accepted

## Context

Vigil needs to retrieve CVE and vulnerability data for npm packages. Multiple sources exist:

- National Vulnerability Database (NVD) - comprehensive but no direct package lookup
- npm audit API - npm-specific but limited detail
- OSV (Open Source Vulnerabilities) - structured, package-agnostic, well-maintained

## Decision

Use OSV API (https://api.osv.dev) as primary vulnerability data source.

## Rationale

1. **Package-focused**: OSV supports PURL (Package URL) format, direct lookup by package name and version
2. **Reliable**: Maintained by Google, updated regularly with CVEs from multiple sources
3. **Structured data**: Returns consistent JSON with affected versions, references, severity
4. **Free/Public**: No authentication required, no rate limiting stated
5. **Comprehensive**: Includes NVD, GitHub Security Advisories, and other databases
6. **Offline caching possible**: Results can be cached locally for repeated lookups

## Implementation

- Endpoint: `POST https://api.osv.dev/v1/query`
- Request: `{"package": {"purl": "pkg:npm/express@4.18.0"}}`
- Caching: Store results in `.vigil.cache` to avoid repeated API calls
- Timeout: 10 seconds per query (configurable)

## Consequences

- Depends on external API availability
- Network requests required for fresh data
- Must handle API errors gracefully (offline mode with cache fallback)
- Rate limits not documented; monitor for issues

## Alternatives Considered

- **npm audit API**: Limited to npm packages, less structured output
- **NVD**: Requires separate package version lookup, no direct integration
