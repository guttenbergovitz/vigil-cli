# ADR 006: Internal-by-Default Project Structure

## Status
Accepted

## Context
The previous project structure (ADR 003) followed the "Standard Go Project Layout" with a `pkg/` directory for public library code and `internal/` for private code. However, `vigil-cli` is primarily a CLI application, not a library intended for external consumption. Exposing packages in `pkg/` creates an implicit promise of API stability that restricts refactoring and evolution.

Additionally, package names like `scanner` and `orchestrator` were generic and technical, rather than domain-specific.

## Decision
Adopt an "Internal-by-Default" structure with Domain-Driven Design naming conventions.

1.  **Move `pkg/` to `internal/`**: All application code (models, config, export) is now private by default. This allows for aggressive refactoring without breaking external contracts.
2.  **Rename Packages**:
    *   `internal/scanner` -> `internal/lockfile`: Explicitly named after its responsibility (parsing lock files).
    *   `internal/orchestrator` -> `internal/scan`: Named after the core business domain (scanning).
    *   `pkg/models` -> `internal/types`: Shared domain types.

## Rationale
1.  **Encapsulation**: Prevents accidental usage of internal APIs by other tools, allowing us to change internal interfaces freely.
2.  **Clarity**: Package names now reflect *what* they do in the business domain (`lockfile`, `scan`), not *how* they do it (`scanner`, `orchestrator`).
3.  **Simplicity**: Removes the decision overhead of "should this be in `pkg` or `internal`?". Default is `internal`.

## Consequences
- **Supersedes**: ADR 003.
- All imports must be updated (completed in refactor).
- External tools cannot import `vigil` packages directly (desired behavior for a CLI app).
