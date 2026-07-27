# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-07-27

### Added

- **Containerization & Nix Flake support** (ADR 003)
  - Multi-stage `Dockerfile` for minimal Alpine-based runtime (~20MB)
  - `flake.nix` with hermetic Go builds, development shell, and `nix run` support
  - Comprehensive Taskfile automation for Docker (`docker-build`, `docker-run`, `docker-scan`, `docker-push`, `docker-clean`)
  - Comprehensive Taskfile automation for Nix (`nix-build`, `nix-run`, `nix-scan`, `nix-shell`, `nix-check`)

### Changed

- Replaced Makefile with Taskfile for build automation
  - Uses go-task/task for cross-platform build system
  - Native host architecture detection
  - Cleaner YAML syntax
  - Same functionality (build, install, test, clean, version)

## [1.0.0] - 2026-07-27

### Added

- **Remote repository scanning** - Scan GitHub, Bitbucket, and other git repositories directly without manual cloning
  - Support for HTTPS, HTTP, SSH, and git@ URL formats
  - Automatic shallow clone (`--depth 1`) to temp directory
  - GITHUB_TOKEN environment variable support for private repositories
  - SSH key support via system git configuration
  - Automatic cleanup of temp directories on success or failure
- **Temporal false positive filtering** - Eliminates 30-40% of false positives by filtering vulnerabilities published before package release dates
  - npm registry integration to fetch package release dates
  - Conservative filtering approach (includes vulnerabilities when dates unavailable)
  - Reduces noise in security reports significantly
- **Full dependency chain tracking** - Complete transitive dependency paths for all lock file types
  - npm package-lock.json now shows full dependency graphs with parent→child relationships
  - Yarn lock files now parse dependencies and build complete graphs
  - All lock file formats (npm, Yarn, pnpm) provide identical path visibility
  - GetVulnerablePath works consistently across all package managers
- **Comprehensive documentation** - Well-structured documentation in ./documentation
  - Getting Started guides (installation, quick start, examples)
  - User Guide (commands reference, reports interpretation, troubleshooting)
  - Architecture documentation (overview, components, data flow)
  - Development guides (setup, contributing, testing)

### Changed

- Refactored codebase to remove dead code and improve maintainability
  - Removed unused config module (265 lines)
  - Centralized severity mapping and ranking logic
  - Extracted CVSS utility functions to types package
  - Removed 4 unused graph methods
- Updated lock file parsing to use graph parsers for all formats
  - npm and Yarn parsers now build full dependency graphs
  - Consistent graph structure across all lock file types
- Improved report formats to show dependency chains for all lock file types

### Fixed

- Dependency paths now work for npm and Yarn (previously only pnpm)
- Temporal filtering prevents reporting of vulnerabilities that predate package releases

### Removed

- Deleted entire internal/config module (unused)
- Removed unused graph traversal methods
- Cleaned up duplicate severity mapping code

## [0.1.0] - Initial development

### Added

- Initial vulnerability scanning for JavaScript/TypeScript projects
- Support for npm, Yarn, and pnpm lock files
- Multi-source CVSS enrichment (OSV, NVD, GitHub Security Advisories)
- Interactive TUI with real-time progress
- Multiple report formats (table, security, text, CSV, markdown, JSON)
- Intelligent risk assessment with exploit classification
- Release gate recommendations
- CI/CD integration with configurable failure thresholds

[Unreleased]: https://github.com/guttenbergovitz/vigil-cli/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/guttenbergovitz/vigil-cli/releases/tag/v1.0.0
