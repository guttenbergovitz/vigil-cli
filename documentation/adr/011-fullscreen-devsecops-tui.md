# ADR 011: Fullscreen DevSecOps Dashboard TUI Architecture

## Status

Accepted

## Context

Vigil CLI previously featured a basic scanning progress TUI. Security engineers required a comprehensive, interactive operator dashboard capable of:
1. Navigating full-spectrum security domain findings (SCA vulnerabilities, Hardcoded Secrets, IaC misconfigurations, License risks, Dependency Graph).
2. Grouping findings interactively (by package/file, by severity, or flat view).
3. Inspecting explicit "Reason Why Flagged" justifications alongside exact dependency chain paths.
4. Exporting scan findings directly from the TUI to JSON, CSV, Markdown, CycloneDX v1.5, and SPDX v2.3 SBOM formats.
5. Providing a modern Neovim / Nerd Fonts aesthetic without standard emojis.

## Decision

We decision to implement a fullscreen DevSecOps Dashboard TUI in `internal/ui` using Charm's `bubbletea`, `lipgloss`, `bubbles/table`, and `bubbles/viewport`:

### 1. Multi-Tab Architecture (`ActiveTab`)
- `[1] Vulns (SCA)`: Software Composition Analysis vulnerabilities with CVSS scores and dependency chain trees.
- `[2] Secrets`: Hardcoded API keys, AWS credentials, SSH keys, and DB passwords with Shannon entropy scores.
- `[3] IaC Security`: Dockerfile and GitHub Actions workflow security misconfigurations with rule IDs.
- `[4] Licenses`: Permissive vs Copyleft open-source license compliance risks.
- `[5] Dep Graph`: Interactive dependency graph tree explorer.

### 2. Live Grouping Engine (`GroupMode`)
- `GroupFlat`: Flat list of findings sorted by severity.
- `GroupPackage`: Grouped by target package or source file name.
- `GroupSeverity`: Grouped by severity tier (Critical, High, Medium, Low, Secret, IaC).

### 3. Explicit Justification ("Reason Why Flagged")
- Every security finding includes a dedicated `ReasonFlagged` field explaining the precise trigger condition.

### 4. Interactive Export Modal
- Pressing `[e]` opens an export dialog rendering reports in JSON, CSV, Markdown, CycloneDX v1.5, or SPDX v2.3 directly to disk.

### 5. Nerd Fonts Aesthetics
- Clean terminal icons (`󰅚 `, `󰀦 `, `󰌵 `, `󰌆 `, `󰄬 `, `󰒍 `, `󰍉 `) used alongside high-contrast Lipgloss badges.

## Consequences

### Positive
- Rich operator experience for AppSec teams and security analysts.
- Single unified TUI covering SCA, Secrets, IaC, Licenses, and SBOM exports.
- Fast, responsive Bubble Tea state management.

### Negative
- Requires terminal window height of at least 20 lines for optimal split-view rendering.
