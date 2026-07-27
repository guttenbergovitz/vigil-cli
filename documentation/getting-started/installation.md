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

## Option 3: Development Build

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
