# Installation

## Prerequisites

- Go 1.24+ (`go version` to check)
- Git (for source installation)

## Option 1: go install (Recommended)

Install latest release directly from source:

```bash
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

Binary installed to `$GOPATH/bin` (typically `~/go/bin`).

Verify installation:

```bash
vigil version
```

## Option 2: Build from Source

Install task runner (if not installed):

```bash
go install github.com/go-task/task/v3/cmd/task@latest
```

Clone and build:

```bash
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli

# Build with version info using Taskfile (recommended)
task build

# Or build directly (no version injection)
go build -o vigil ./cmd/vigil
```

Taskfile automatically injects version, commit hash, and build date:

```bash
task                # Build binary (default task)
task build          # Build binary with version info
task install        # Install to $GOPATH/bin with version info
task version        # Show current version information
task test           # Run tests
task clean          # Remove build artifacts
task --list         # List all available tasks
```

Move to PATH:

```bash
# macOS/Linux
sudo mv vigil /usr/local/bin/

# or use without install
./vigil scan .
```

## Option 3: Docker Container

Run without installing Go or language runtimes:

```bash
# Pull from DockerHub
docker pull guttenbergovitz/vigil:latest

# Scan local directory (JS/TS, Python, Rust, PHP, Go, Java)
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan .

# Scan specific lockfile in polyglot repo
docker run --rm -v "$(pwd):/scan" guttenbergovitz/vigil:latest scan . --lockfile uv.lock

# With API keys for better rate limits
docker run --rm \
  -v "$(pwd):/scan" \
  -e NVD_API_KEY="${NVD_API_KEY}" \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  guttenbergovitz/vigil:latest scan .

# Check version
docker run --rm guttenbergovitz/vigil:latest version
```

**Build locally**:

```bash
task docker-build
docker run --rm -v "$(pwd):/scan" vigil:latest scan .
```

**Environment variables**:
- `NVD_API_KEY` - Improves NVD rate limits (5/30s → 50/30s)
- `GITHUB_TOKEN` - For private repos and GHSA rate limits

## Option 4: Nix Flake

For Nix users:

```bash
# Run directly from GitHub
nix run github:guttenbergovitz/vigil-cli -- scan .

# Build locally
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli
nix build
./result/bin/vigil version

# Development shell with all tools
nix develop
```

Nix provides reproducible, declarative builds with zero configuration.

## Option 5: Development Build

For contributing or testing unreleased features:

```bash
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli
go mod tidy
go build -o vigil ./cmd/vigil
```

See [Development Setup](../development/setup.md) for full development environment.

## Environment Variables (Optional)

Enhance data quality with API keys:

```bash
# NVD API key for authoritative CVE data
export NVD_API_KEY="your-key-here"

# GitHub token for GHSA data (improves rate limits)
export GITHUB_TOKEN="ghp_your-token-here"
```

### Getting API Keys

**NVD API Key:**
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill request form
3. Receive key via email

**GitHub Token:**
1. Visit https://github.com/settings/tokens
2. Generate new token (classic)
3. Select `public_repo` scope (read-only)

## Verification

Run first scan:

```bash
cd /path/to/your/node/project
vigil scan .
```

Should display interactive TUI with scan progress.

## Uninstall

```bash
# go install method
rm $(which vigil)

# manual install
sudo rm /usr/local/bin/vigil
```

## Troubleshooting

**"vigil: command not found":**
- Add `$GOPATH/bin` to PATH: `export PATH=$PATH:$(go env GOPATH)/bin`
- Or use absolute path: `~/go/bin/vigil`

**"missing go.sum entry":**
- Run `go mod tidy` in project directory

**Build errors:**
- Ensure Go 1.24+: `go version`
- Update dependencies: `go get -u ./...`

See [Troubleshooting Guide](../user-guide/troubleshooting.md) for more issues.

## Next Steps

- [Quick Start](quick-start.md) - Run your first scan
- [Commands Reference](../user-guide/commands.md) - Full CLI documentation
