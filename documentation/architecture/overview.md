# Architecture Overview

System design and core concepts.

## Design Principles

**1. Single-purpose CLI**
- One tool, one job: scan JS/TS dependencies for vulnerabilities
- No plugins, extensions, or feature creep

**2. API-first enrichment**
- Aggregate data from multiple authoritative sources
- NVD, GitHub Security Advisories, OSV
- Best-available CVSS scores

**3. Zero runtime dependencies**
- Standalone Go binary
- No Node.js, Python, or external tools required

**4. Fast and respectful**
- Rate-limited API calls
- Caching to avoid redundant scans
- Concurrent where possible, sequential where required

**5. Production-ready output**
- Multiple formats for different audiences
- Executive summaries for stakeholders
- Technical details for engineers

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  vigil scan | vigil report | vigil ci                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                    Scan Orchestrator                         │
│  • Lock file detection                                       │
│  • Dependency tree parsing                                   │
│  • API query coordination                                    │
│  • Results aggregation                                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┼──────────┬──────────────┐
        │          │          │              │
┌───────▼────┐ ┌──▼────┐ ┌───▼────┐ ┌──────▼──────┐
│    OSV     │ │  NVD  │ │ GitHub │ │  Lockfile   │
│   Client   │ │ Client│ │ Client │ │   Parser    │
└────────────┘ └───────┘ └────────┘ └─────────────┘
        │          │          │              │
┌───────▼──────────▼──────────▼──────────────▼─────┐
│              Data Enrichment Layer                │
│  • CVSS score prioritisation                      │
│  • Exploit type classification                    │
│  • Risk scoring                                   │
│  • Dependency path resolution                     │
└───────────────────────┬───────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────┐
│                Report Generator                    │
│  • Table, Text, Security, CSV, Markdown, JSON     │
│  • Release gate recommendations                   │
│  • Filtering and sorting                          │
└───────────────────────┬───────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────┐
│                    TUI/Output                      │
│  • Interactive progress display                    │
│  • Formatted reports                               │
│  • File export                                     │
└────────────────────────────────────────────────────┘
```

## Data Flow

### Scan Phase

1. **Detect lock file** - Find supported lock file in project
2. **Parse dependencies** - Extract full dependency tree
3. **Tag types** - Classify as production/development
4. **Query OSV** - Primary vulnerability source
5. **Enrich NVD** - Get authoritative CVE data for CVE-* IDs
6. **Enrich GitHub** - Get GHSA data for GHSA-* IDs
7. **Calculate risk** - Compute risk scores based on context
8. **Cache results** - Save to `.vigil.cache`

### Report Phase

1. **Load cache** - Read `.vigil.cache` from previous scan
2. **Filter** - Apply severity/type filters
3. **Classify** - Determine exploit types and exploitability
4. **Format** - Generate requested output format
5. **Gate decision** - Compute release recommendation
6. **Output** - Display or export

## Key Components

**cmd/vigil** - Entry point, command routing

**internal/cli** - Command implementations (scan, report, ci)

**internal/scan** - Scan orchestration, API coordination

**internal/lockfile** - Lock file parsing (npm, Yarn, pnpm)

**internal/osv** - OSV API client

**internal/nvd** - NVD API client

**internal/github** - GitHub Security Advisories client

**internal/report** - Report generation and formatting

**internal/types** - Core data structures (Dependency, Vulnerability, ScanResult)

**internal/ui** - TUI (Terminal UI) for interactive display

## Concurrency Model

**Sequential API calls** - Respect rate limits:
- OSV: 10ms delay between requests
- NVD: 6s (no key) or 600ms (with key) delay
- GitHub: standard HTTP rate limiting

**Parallel processing** - Where safe:
- Lock file parsing (independent of API calls)
- Report formatting (independent of data fetching)

## Caching Strategy

**Cache key**: SHA256 hash of lock file content

**Cache invalidation**: Hash mismatch triggers rescan

**Cache location**: `.vigil.cache` in scanned directory

**Cache format**: JSON (ScanResult struct)

**Why cache**:
- Avoid redundant API calls
- Speed up repeated scans
- Enable offline report generation

## Error Handling

**Fail fast**: Exit on critical errors (missing lock file, invalid config)

**Graceful degradation**: Continue on non-critical errors (single package query failure)

**User feedback**: Clear error messages with actionable solutions

## Security Considerations

**API keys**: Environment variables only (never committed)

**Network**: HTTPS for all API calls

**Input validation**: Lock file parsing validates structure before processing

**No code execution**: Static analysis only, never executes dependencies

## Performance Characteristics

**Scan time**: Depends on dependency count and API keys
- ~283 deps: 2-3 minutes without keys, 30-60 seconds with keys
- Rate limiting is primary bottleneck

**Memory**: ~50-100MB for typical projects

**Disk**: Negligible (.vigil.cache typically <1MB)

## Extensibility

**Not designed for plugins** - Focused, single-purpose tool

**Extensibility through output formats** - JSON export enables custom processing

**API clients are swappable** - Implement same interface for alternative data sources

## Next Steps

- [Components](components.md) - Internal package details
- [Data Flow](data-flow.md) - Detailed pipeline walkthrough
- [ADRs](../adr/) - Architecture decision records
