# ADR 004: Scan Results Caching

## Status
Accepted

## Context

Vigil scans can query hundreds of dependencies against OSV API. Repeating full scans for CI runs, reports, and incremental updates is wasteful and slow.

## Decision

Cache scan results in `.vigil.cache` (local JSON file) after each scan.

## Implementation

**Cache format:** JSON at `.vigil.cache`

```json
{
  "version": 1,
  "project_path": "/path/to/project",
  "scanned_at": "2025-12-04T10:30:00Z",
  "lock_file": "package-lock.json",
  "lock_file_hash": "abc123...",
  "dependencies": [
    {
      "name": "express",
      "version": "4.18.0",
      "type": "production",
      "vulnerabilities": [
        {
          "id": "CVE-2024-1234",
          "severity": "medium",
          "summary": "XSS in template",
          "risk_score": 45
        }
      ]
    }
  ]
}
```

**Cache invalidation:**
- Automatically invalidated if lock file hash changes (detected via `hash` field)
- Manual invalidation: user deletes `.vigil.cache`
- TTL: None (valid until lock file changes)

**Usage:**
- `vigil scan` always creates fresh cache
- `vigil report` reads from cache (no API calls)
- `vigil ci` reads from cache

## Rationale

1. **Performance**: Report generation doesn't re-query API
2. **Offline capability**: Reports work without network after scan
3. **Cheap reproduction**: Developers can run `vigil report --filter high` without rescanning
4. **CI efficiency**: `vigil ci` gate is fast and deterministic

## Consequences

- Cache must be committed to repo (or ignored)—decision deferred to user
- Stale cache if lock file manually edited without scan
- Lock file hash prevents obvious cache corruption

## Alternatives Considered

- **No cache**: Every report requires full API scan (slow, wasteful)
- **Database cache**: Over-engineered for CLI tool
- **Global cache**: Would share data across projects (confusing)
