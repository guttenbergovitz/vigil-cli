# ADR 009: Full-Spectrum Security & SBOM Engine Architecture

## Status

Accepted

## Context

Vigil CLI was initially designed for Software Composition Analysis (SCA) across multiple language ecosystems (JS/TS, Python, Rust, PHP, Go). Modern DevSecOps pipelines require a comprehensive security analysis covering:

1. **Hardcoded Secrets Detection**: Preventing accidental credential leaks in source code and configuration files.
2. **License Compliance**: Identifying copyleft or legally restrictive licenses (GPL, AGPL).
3. **Container & IaC Security**: Auditing Dockerfiles and CI/CD workflows for security misconfigurations.
4. **Software Bill of Materials (SBOM)**: Generating standard CycloneDX and SPDX files for supply chain transparency.

## Decision

We decision to extend Vigil CLI with four modular, decoupled security analysis packages under `internal/`:

### 1. Secret Scanner (`internal/secrets`)

- Implement a high-performance pattern matching engine combining curated regular expressions and Shannon entropy analysis (threshold > 4.5).
- Scan source files and configuration files while respecting `.gitignore` and excluding binary/build artifacts.
- Detect AWS keys, GitHub tokens, Slack webhooks, private SSH keys, JWT tokens, and database URIs with embedded passwords.

### 2. License Compliance Scanner (`internal/license`)

- Aggregate package license metadata across ecosystems.
- Categorize licenses into **Permissive** (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause) and **Copyleft / Restrictive** (GPL-2.0, GPL-3.0, AGPL-3.0, LGPL).
- Support release gate filtering via `--fail-on-license copyleft`.

### 3. Container & IaC Linter (`internal/container`)

- Audit `Dockerfile` for security anti-patterns (running as `root`, using `:latest` base image tags, uncleaned package caches).
- Audit `.github/workflows/*.yml` for supply chain risks (unpinned Action commit SHAs, insecure `pull_request_target` triggers).

### 4. SBOM Generator (`internal/sbom`)

- Transform `types.DependencyGraph` and metadata into standard **CycloneDX v1.5 JSON** and **SPDX v2.3 JSON** specifications.
- Support export via `vigil report --format cyclonedx` and `vigil report --format spdx`.

## Consequences

### Positive

- **Comprehensive Security**: Single CLI covering SCA, Secret Detection, IaC Linting, and SBOM Generation.
- **Supply Chain Compliance**: Meets NIST/CISA SBOM mandates for commercial and enterprise software.
- **Fast Execution**: Pure Go implementation using stdlib regex and math with zero external subprocess calls.

### Negative

- Secret detection rules require ongoing tuning to balance sensitivity and false-positive rates.

## Related

- ADR 002: OSV API Integration
- ADR 003: Containerization Strategy
- ADR 008: Multi-Ecosystem Support
