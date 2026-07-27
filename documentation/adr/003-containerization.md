# ADR 003: Containerization Strategy

## Status

Accepted

## Context

Vigil needs to run in diverse environments (CI/CD, developer machines, servers). Users may not have Go installed or may prefer isolated environments. Container and Nix support enables:

- Reproducible builds across platforms
- Isolated execution environments
- Easy CI/CD integration
- Declarative dependency management
- No local Go installation required

## Decision

Support three containerization approaches:

### 1. Docker Container

**Build**: Multi-stage Dockerfile with Alpine Linux

**Runtime Image**: `alpine:latest` (~5MB base + ~15MB binary)

**Why Alpine**:
- Minimal size while including shell for debugging
- CA certificates included (required for HTTPS API calls)
- Package manager available (apk) for troubleshooting
- Wide compatibility

**Alternatives considered**:
- `scratch`: Smallest possible (just binary) but no CA certs, no shell, harder to debug
- `distroless`: Good middle ground but larger than Alpine
- Debian-slim: Too large (~70MB vs ~5MB)

**Version Injection**: Build args pass version, commit, date to ldflags

**Publishing**: DockerHub at `guttenbergovitz/vigil`

### 2. Nix Flake

**Why Nix**:
- Declarative, reproducible builds
- Zero-config dev environments
- Hermetic builds (no hidden dependencies)
- Popular in security-conscious teams

**Implementation**: `flake.nix` with:
- Default package: `nix build`
- Development shell: `nix develop`
- Direct run: `nix run github:guttenbergovitz/vigil-cli`

### 3. Native Binary (existing)

Keep native builds via:
- `go install` for Go users
- `task build` for source builds

## Consequences

### Positive

- **Portability**: Run on any platform with Docker or Nix
- **CI/CD Integration**: Easy to use in pipelines
- **Reproducibility**: Identical builds across environments
- **Isolation**: No conflict with local dependencies
- **Zero Install**: Docker/Nix users don't need Go
- **Flexibility**: Three deployment methods for different use cases

### Negative

- **Maintenance**: Three build methods to maintain
- **Image Size**: Docker image ~20MB (binary + Alpine)
- **Startup Time**: Container overhead (negligible for CLI)
- **Learning Curve**: Users need Docker/Nix knowledge

### Neutral

- **Environment Variables**: Must be passed to containers
  - `NVD_API_KEY` - Optional, improves NVD rate limits
  - `GITHUB_TOKEN` - Optional, for private repos and rate limits

## Implementation

### Docker Usage

```bash
# Build
docker build -t vigil:latest .

# Run
docker run --rm vigil:latest version

# Scan local directory
docker run --rm -v "$(pwd):/scan" vigil:latest scan .

# With API keys
docker run --rm \
  -v "$(pwd):/scan" \
  -e NVD_API_KEY="${NVD_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  vigil:latest scan .

# Pull from DockerHub
docker pull guttenbergovitz/vigil:latest
```

### Nix Usage

```bash
# Build
nix build

# Run
nix run github:guttenbergovitz/vigil-cli -- version

# Development shell
nix develop

# Scan local directory
nix run github:guttenbergovitz/vigil-cli -- scan .
```

### Environment Variables

Both Docker and Nix honor these environment variables:

- `NVD_API_KEY`: NVD API key (optional, improves rate limits from 5/30s to 50/30s)
- `GITHUB_TOKEN`: GitHub token (optional, for private repos and GHSA rate limits)

Without keys, Vigil works but API rate limits apply.

## Related

- ADR 001: Lock file support
- ADR 002: (if exists - CVSS enrichment strategy)

## References

- [Docker Multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Alpine Linux](https://alpinelinux.org/)
