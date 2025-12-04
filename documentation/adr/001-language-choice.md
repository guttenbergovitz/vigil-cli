# ADR 001: Go as Primary Language

## Status
Accepted

## Context

Vigil CLI needs to be lightweight, fast, and distributable as a single binary. The tool must:
- Run standalone without runtime dependencies
- Parse lock files efficiently
- Make HTTP requests to OSV API
- Export to multiple formats (CSV, Markdown, JSON)

## Decision

Use Go 1.25 for Vigil CLI implementation.

## Rationale

1. **Single binary distribution**: Go compiles to a single binary, no runtime required
2. **Performance**: Fast startup, minimal memory footprint
3. **Cross-platform**: Easy compilation to macOS, Linux, Windows
4. **Standard library**: Sufficient for JSON, CSV, HTTP, file operations
5. **Tooling**: Strong testing, formatting, linting infrastructure
6. **Idioms**: Well-established patterns for CLI tools (Cobra, etc.)

## Consequences

- Go Standard Library only for core functionality (no third-party deps except for CLI framework)
- All lock file parsing must be implemented from scratch or with minimal dependencies
- JSON marshaling/unmarshaling for caching and API responses

## References

- Go 1.25 release notes
- Standard library: `encoding/json`, `encoding/csv`, `net/http`
