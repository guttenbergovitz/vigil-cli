# ADR 008: Multi-Ecosystem Vulnerability Scanning Strategy

## Status

Accepted

## Context

Vigil CLI was initially built to scan JavaScript and TypeScript projects (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`). Modern development teams work with polyglot repositories containing microservices or modules written in **Python**, **Rust**, **PHP**, and **Go**.

Expanding Vigil to scan multi-language projects allows security teams to use a single, unified CLI scanner without sacrificing scan speed, dependency graph accuracy, or clean output reporting.

## Decision

We decision to extend Vigil CLI into a multi-ecosystem scanner through the following architectural design:

### 1. Ecosystem Abstraction (`types.Ecosystem`)

Introduce an explicit `types.Ecosystem` abstraction (`npm`, `PyPI`, `Cargo`, `Go`, `Packagist`). Every dependency node and graph retains its ecosystem metadata to construct correct Package URL (PURL) targets for vulnerability databases:

- **npm**: `pkg:npm/<package>@<version>`
- **Python**: `pkg:pypi/<package>@<version>`
- **Rust**: `pkg:cargo/<package>@<version>`
- **PHP**: `pkg:composer/<package>@<version>`
- **Go**: `pkg:golang/<package>@<version>`

### 2. Priority-Based Lockfile Detection & User Override

Implement automatic lockfile resolution in `FindLockFile` ordered by graph precision:

1. **Python**: `uv.lock` > `poetry.lock` > `Pipfile.lock` > `requirements.txt`
2. **JavaScript/TypeScript**: `pnpm-lock.yaml` / `package-lock.json` / `yarn.lock`
3. **Rust**: `Cargo.lock`
4. **PHP**: `composer.lock`
5. **Go**: `go.mod`

For polyglot repositories with multiple lockfiles in a single directory, add a `--lockfile <filename>` CLI flag for explicit user control.

### 3. Hybrid Vulnerability & CVSS Enrichment

Retain the hybrid vulnerability enrichment pipeline across all ecosystems:
- **OSV API** as the primary multi-ecosystem aggregator.
- **NVD API & GitHub Security Advisories** for CVE/GHSA score enrichment and CVE title/description resolution.

### 4. Incremental TDD Rollout

Roll out ecosystem support incrementally using Test-Driven Development (TDD) with dedicated test fixtures in `test-project/<language>/`:

- **Phase 1 & 2**: Multi-ecosystem core refactoring & Python support (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`).
- **Phase 3**: Rust support (`Cargo.lock`).
- **Phase 4**: PHP support (`composer.lock`).
- **Phase 5**: Go support (`go.mod`).

## Consequences

### Positive

- **Polyglot scanning**: Single tool for JS, Python, Rust, PHP, and Go repositories.
- **Modern Python tooling**: First-class support for `uv` (`uv.lock`), Poetry, Pipenv, and pip.
- **Consistent reporting**: Identical TUI, CSV, Markdown, and JSON vulnerability reports across all languages.
- **Hermetic & stdlib-first**: Clean, fast parsers without heavy external runtime dependencies.

### Negative

- Additional lockfile formats to maintain as package manager formats evolve.
- Flat lockfile formats (like basic `requirements.txt`) lack transitive dependency graph information compared to full lockfiles (`uv.lock`, `package-lock.json`).

## Related

- ADR 002: OSV API Integration
- ADR 003: Containerization Strategy
- ADR 005: Multi-Source CVSS Enrichment
