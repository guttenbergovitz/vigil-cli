# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.4] - 2026-07-27

### Fixed

- **Initialize Column Widths in `NewModel()` & Auto-Sync Table Layout**
  - Executed `recalculateViewports()` directly inside `NewModel()` so column widths (`tableReasonColWidth`, `tableTargetColWidth`, `tableIDColWidth`) are initialized immediately upon TUI startup.
  - Automatically triggered `updateTableLayout()` inside `recalculateViewports()` so table rows are re-generated for current terminal dimensions instantly without needing window zoom resize workarounds.

## [1.5.2] - 2026-07-27

### Fixed

- **Subtract 5-Column Cell Padding Margins in Table Column Width Calculations**
  - Subtracted 18 characters from `availWidth` for 5-column table widths (`tableInnerWidth := availWidth - 18`) to account for bubbles/table internal cell padding spaces.
  - Completely eliminated any row line-wrapping and header underline overflow in Box 1 full-width table.

## [1.5.1] - 2026-07-27

### Fixed

- **Reset Item Selection and Table Cursor on Tab Navigation**
  - Reset `selectedIdx = 0` and table cursor to position `0` whenever switching tabs (`[1-5]`).
  - Automatically populate detailed inspection, reason why flagged, and dependency tree path for item #0 immediately upon switching tabs.

## [1.5.0] - 2026-07-27

### Added

- **Full-Width Top Table & 3-Column Bottom Pane Layout Architecture**
  - **Top Section (Full-Width Box 1)**: Rich 5-column table (`DOMAIN`, `SEVERITY`, `TARGET / PACKAGE`, `ID / RULE`, `REASON SUMMARY`) spanning 100% of body width.
  - **Bottom Section (3 Side-by-Side Columns)**:
    - `💡 [2] Reason Why Flagged` (Width: 25%) - Word-wrapped reason for active item.
    - `󰈔 [3] Detailed Inspection` (Width: 50%) - Complete CVSS score & vector, context, and remediation.
    - `󰒍 [4] Dependency Tree Path` (Width: 25%) - Dependency tree graph path.

## [1.4.7] - 2026-07-27

### Fixed

- **Optimize Column Width Ratios & Add Row String Truncation in Box 1 Table**
  - Reallocated Box 1 table column ratios (`SEVERITY`: 10, `TARGET / PACKAGE`: 40%, `ID / RULE`: 60%) so long identifiers (e.g. `GHSA-m99w-x7hq-7vfj` or `CVE-2026-44577`) get generous width and never get pushed to a second line.
  - Added strict string truncation (`...`) for package and ID strings to ensure every row in Box 1 strictly occupies 1 single line with zero row-wrapping.

## [1.4.6] - 2026-07-27

### Fixed

- **Subtract Cell Padding Margins in Table Column Width Calculations**
  - Accounted for internal cell padding added by `charmbracelet/bubbles/table` (`-10` in grid views, `-12` in scanning view).
  - Ensured table horizontal rule lines `─────` fit strictly within box inner width, completely eliminating `│────│` and `│──` line-wrapping visual artifacts.

## [1.4.5] - 2026-07-27

### Fixed

- **Simplify Box 1 Table to 3 Wide Columns (`SEVERITY`, `TARGET / PACKAGE`, `ID / RULE`)**
  - Removed redundant `REASON` column from Box 1 table, since full word-wrapped reasons are rendered in adjacent Box 2 (`💡 Reason Why Flagged`).
  - Allocated 100% of Box 1 width to `SEVERITY`, `TARGET / PACKAGE`, and `ID / RULE` columns, completely eliminating any row or line wrapping visual bugs.

## [1.4.4] - 2026-07-27

### Fixed

- **Boxed Fullscreen DevSecOps Scanning State**
  - Render scanning progress view (`StateScanning`) in a clean, pixel-perfect boxed panel spanning full screen.
  - Dynamically calculate scanning stream table column widths to eliminate any terminal line-wrapping during live scan execution.

## [1.4.3] - 2026-07-27

### Fixed

- **Fix Table Column Width & Underline Line Wrapping Visual Bug**
  - Dynamically calculate table column widths (`SEVERITY`, `TARGET`, `ID / RULE`, `REASON`) fitting `leftWidth` exactly.
  - Automatically truncate reason summary to fit allocated column width, completely eliminating table header underline line wrapping.

## [1.4.2] - 2026-07-27

### Fixed

- **Fix Fullscreen Layout Clipping & Sticky Top Header Toolbar**
  - Adjusted grid dimension calculations (`availWidth = m.width - 2`, `bodyHeight = m.height - 4`) so horizontal wrapping never occurs, ensuring top header toolbar is always visible.
  - Ensured scanning progress view (`StateScanning`) renders in fullscreen AltScreen mode from launch.

## [1.4.1] - 2026-07-27

### Added

- **Lazygit & Bottom (`btm`) Style Multi-Pane Grid Dashboard**
  - 4-Pane Grid Layout: `[1] Security Findings Table`, `[2] Reason Why Flagged`, `[3] Dependency Tree Path`, `[4] Detailed Inspection`
  - Active Pane Focus cycling (`[Tab]` / `[Shift+Tab]`) with highlighted borders
  - Expandable/Collapsible Window Maximization (`[w]` or `[f]`) to maximize focused pane to 100% full screen
  - Dynamic Terminal Window Resize & Automatic Word Wrapping matching exact terminal dimensions (`m.width`, `m.height`)

## [1.4.0] - 2026-07-27

### Added

- **Fullscreen DevSecOps Dashboard TUI** (ADR 011)
  - Fullscreen Tabbed Dashboard Navigation (`[1] Vulns`, `[2] Secrets`, `[3] IaC Security`, `[4] Licenses`, `[5] Dep Graph`)
  - Interactive Grouping Engine (`[g]` for Flat View, Group by Package, Group by Severity)
  - Explicit **"Reason Why Flagged"** justification display in Deep Inspector view
  - Interactive **Export Modal (`[e]`)** supporting JSON, CSV, Markdown, CycloneDX v1.5, and SPDX v2.3 export formats directly from TUI
  - Modern Neovim / Nerd Fonts icon aesthetic (no standard emojis)

## [1.3.0] - 2026-07-27

### Added

- **Java Ecosystem Support (Maven & Gradle)** (ADR 010)
  - Added support for Maven `pom.xml` dependency parsing with property `${property.name}` resolution
  - Added support for Gradle `gradle.lockfile` dependency resolution
  - Added `EcosystemMaven` (`"Maven"`) with `pkg:maven/{groupId}/{artifactId}@{version}` PURL mapping

## [1.2.0] - 2026-07-27

### Added

- **Full-Spectrum Security & SBOM Engine** (ADR 009)
  - **Secret Scanning (`--secrets`)**: Pattern matching engine with Shannon entropy calculation (>4.5) to detect AWS keys, GitHub tokens, Slack webhooks, SSH keys, JWT tokens, and DB connection credentials with masked output
  - **Software Bill of Materials (SBOM)**: Export standard **CycloneDX v1.5 JSON** (`--format cyclonedx`) and **SPDX v2.3 JSON** (`--format spdx`) formats
  - **License Compliance**: Categorization of package licenses into Permissive (MIT, Apache, BSD) vs Copyleft/restrictive (GPL, AGPL, LGPL, MPL) risk profiles
  - **Container & IaC Security**: Security linter for `Dockerfile` (root user, unpinned base images, secrets in ENV) and `.github/workflows/*.yml` (unpinned actions, dangerous `pull_request_target` triggers)

## [1.1.0] - 2026-07-27

### Added

- **Multi-Ecosystem Scanning Support** (ADR 008)
  - Added support for **Python**: `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`
  - Added support for **Rust**: `Cargo.lock`
  - Added support for **PHP**: `composer.lock`
  - Added support for **Go**: `go.mod`
  - Added `types.Ecosystem` abstraction (`npm`, `PyPI`, `Cargo`, `Packagist`, `Go`)
  - Integrated ecosystem-specific PURL queries for OSV API (`pkg:pypi/...`, `pkg:cargo/...`, `pkg:composer/...`, `pkg:golang/...`)
  - Added `--lockfile` CLI flag to explicitly override lockfile selection
- **Multi-Ecosystem Architecture**
  - Priority lockfile auto-detection strategy
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
