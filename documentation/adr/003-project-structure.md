# ADR 003: Project Structure and Package Organization

## Status
Superseded by [ADR 006](006-internal-by-default.md)

## Context

Go projects require clear separation between binary entry points, internal business logic, and reusable libraries. Different layouts serve different purposes.

## Decision

Adopt standard Go project layout:

```
cmd/vigil/           # CLI binary entry point
internal/
  ├── scanner/       # Dependency tree analysis logic
  ├── ui/            # Terminal UI (TUI) components
  ├── osv/           # OSV API client
  ├── nvd/           # NVD API client
  └── github/        # GitHub Security Advisories API client
pkg/
  ├── config/        # Config file parsing
  ├── models/        # Shared data structures
  └── export/        # Export handlers (CSV, Markdown, JSON)
documentation/       # All project documentation
tests/               # Acceptance and integration tests
```

## Rationale

1. **cmd/**: Single binary (`vigil`) with minimal logic—just flag parsing and orchestration
2. **internal/**: Private packages, not importable by external code—each domain (scanning, reporting, API) isolated
3. **pkg/**: Public libraries for config, models, export formats—potential for reuse or extraction
4. **documentation/**: All non-code docs in one place—easier to maintain
5. **tests/**: Integration and E2E tests separate from unit tests (unit tests stay with code)

## Consequences

- Clear ownership of business domains
- Easy to test each component independently
- Future extraction of `pkg/` modules possible without refactoring
- Developers know where to look for functionality

## Testing Strategy

- Unit tests: colocated with code (`*_test.go` in same package)
- Integration tests: in `tests/` directory (full binary tests)
- No external test runner needed—`go test ./...` runs all
