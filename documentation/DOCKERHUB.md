# Vigil DevSecOps Full-Spectrum Scanner

`guttenbergovitz/vigil` is a lightweight, zero-dependency DevSecOps scanner for multi-ecosystem Software Composition Analysis (SCA), Secret Scanning, License Compliance, SBOM Generation, Container Audit, and IaC Security.

[![Docker Pulls](https://img.shields.io/docker/pulls/guttenbergovitz/vigil)](https://hub.docker.com/r/guttenbergovitz/vigil)
[![Docker Image Size](https://img.shields.io/docker/image-size/guttenbergovitz/vigil/latest)](https://hub.docker.com/r/guttenbergovitz/vigil)
[![GitHub License](https://img.shields.io/github/license/guttenbergovitz/vigil-cli)](https://github.com/guttenbergovitz/vigil-cli)

---

## 🚀 Quick Start

### 1. Scan Local Directory

Run a full security scan on your current working directory:

```bash
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan .
```

### 2. Scan Remote Git Repository

Scan any public or private GitHub/Bitbucket repository directly:

```bash
docker run --rm guttenbergovitz/vigil:latest scan https://github.com/expressjs/express
```

### 3. Interactive DevSecOps Dashboard TUI

Run with terminal interactive TUI enabled (`-it` flag):

```bash
docker run --rm -it -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan .
```

---

## ✨ Features

- **Multi-Ecosystem SCA**: JavaScript/TypeScript (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`), Rust (`Cargo.lock`), PHP (`composer.lock`), Go (`go.mod`), and Java (`pom.xml`, `gradle.lockfile`).
- **Secret Scanning**: Scans codebase for leaked AWS keys, GitHub PATs, Slack Webhooks, DB passwords, and private SSH keys using regex patterns and Shannon entropy analysis.
- **License Compliance**: Identifies Permissive vs Copyleft (GPL, AGPL) risk levels.
- **Container & IaC Security**: Audits Dockerfiles and GitHub Actions workflows for security misconfigurations and root execution risks.
- **Software Bill of Materials (SBOM)**: Generates industry-standard **CycloneDX v1.5** and **SPDX v2.3** JSON formats.
- **Lazygit / `btm` Multi-Pane TUI**: Interactive 4-pane fullscreen terminal dashboard with tabs (`[1-5]`), pane focus (`[Tab]`), pane maximization (`[w/f]`), grouping (`[g]`), search (`[/]`), and export modal (`[e]`).
- **Multiple Export Formats**: JSON, CSV, Markdown, CycloneDX, SPDX.

---

## 🛠️ Environment Variables

Optionally pass API tokens for higher rate limits and enriched vulnerability scoring:

```bash
docker run --rm -v "$(pwd):/scan" \
  -e NVD_API_KEY="your-nvd-api-key" \
  -e GITHUB_TOKEN="your-github-token" \
  guttenbergovitz/vigil:latest scan .
```

---

## 📊 Exporting Reports

To save scan reports directly to your host machine:

```bash
# Save JSON report
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan . --export report.json

# Save CSV report
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan . --export report.csv

# Save CycloneDX v1.5 SBOM
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan . --export sbom.cdx.json
```

---

## 📄 Repository & Documentation

- **GitHub Repository**: [https://github.com/guttenbergovitz/vigil-cli](https://github.com/guttenbergovitz/vigil-cli)
- **Documentation**: [https://github.com/guttenbergovitz/vigil-cli/tree/main/documentation](https://github.com/guttenbergovitz/vigil-cli/tree/main/documentation)
- **Changelog**: [https://github.com/guttenbergovitz/vigil-cli/blob/main/CHANGELOG.md](https://github.com/guttenbergovitz/vigil-cli/blob/main/CHANGELOG.md)
