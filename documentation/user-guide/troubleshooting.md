# Troubleshooting

Common issues and solutions.

## Installation Issues

### "vigil: command not found"

**Cause**: Binary not in PATH.

**Solution**:

```bash
# Check where vigil is installed
which vigil

# If in ~/go/bin, add to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Make permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### "go: cannot find module"

**Cause**: Module not downloaded or outdated go.sum.

**Solution**:

```bash
# Clean module cache
go clean -modcache

# Reinstall
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

### Build errors

**Cause**: Go version too old.

**Solution**:

```bash
# Check Go version
go version

# Ensure Go 1.24+
# Update: https://go.dev/dl/
```

## Scanning Issues

### "No lock file found"

**Cause**: Missing `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`.

**Solution**:

```bash
# npm
npm install

# Yarn
yarn install

# pnpm
pnpm install

# Verify lock file exists
ls -la package-lock.json yarn.lock pnpm-lock.yaml
```

### "Failed to parse lock file"

**Cause**: Corrupted or invalid lock file format.

**Solution**:

```bash
# Delete and regenerate
rm package-lock.json  # or yarn.lock, pnpm-lock.yaml
npm install  # or yarn/pnpm install

# Verify JSON is valid (for package-lock.json)
jq . package-lock.json > /dev/null && echo "Valid" || echo "Invalid"
```

### Scan hangs or takes too long

**Cause**: Rate limiting without API keys.

**Solution**:

```bash
# Set NVD API key for faster NVD queries
export NVD_API_KEY="your-key-here"

# Get key: https://nvd.nist.gov/developers/request-an-api-key

# Verify key is set
echo $NVD_API_KEY
```

**Alternative**: Skip dev dependencies to reduce scan time:

```bash
vigil scan . --skip-devdeps
```

### "OSV API error: connection timeout"

**Cause**: Network issue or OSV API down.

**Solution**:

```bash
# Check connectivity
curl -I https://api.osv.dev/v1

# Check firewall/proxy settings
# Retry scan after network stabilises
```

### "NVD API rate limit exceeded"

**Cause**: Too many requests without API key.

**Solution**:

```bash
# Without key: 5 req/30s (slow)
# With key: 50 req/30s (fast)

export NVD_API_KEY="your-key-here"
vigil scan .
```

## Report Issues

### "load cache: no such file"

**Cause**: No previous scan run or cache deleted.

**Solution**:

```bash
# Run scan first
vigil scan .

# Then generate report
vigil report
```

### Empty report output

**Cause**: No vulnerabilities found or filter too restrictive.

**Solution**:

```bash
# Check total vulns in cache
jq '.total_vulns' .vigil.cache

# Remove filter
vigil report  # without --filter flag

# Try lower filter threshold
vigil report --filter low
```

### "Invalid cache format"

**Cause**: Cache from older version or corrupted.

**Solution**:

```bash
# Delete cache and rescan
rm .vigil.cache
vigil scan .
```

## CI/CD Issues

### CI fails with "vigil: not found"

**Cause**: Binary not installed in CI environment.

**Solution**:

```yaml
# GitHub Actions
- name: Install Vigil
  run: go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest

- name: Add to PATH
  run: echo "$(go env GOPATH)/bin" >> $GITHUB_PATH
```

### Slow CI scans

**Cause**: Downloading all dependencies or rate limiting.

**Solution**:

```yaml
# Cache scan results
- uses: actions/cache@v4
  with:
    path: .vigil.cache
    key: vigil-${{ hashFiles('**/package-lock.json') }}

# Set API keys in secrets
env:
  NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### False CI failures

**Cause**: Dev dependencies counted.

**Solution**:

```bash
# Skip dev deps in CI
vigil scan . --skip-devdeps
vigil ci --fail-on high
```

## Performance Issues

### High memory usage

**Cause**: Large dependency tree.

**Solution**:

```bash
# Monitor memory
/usr/bin/time -v vigil scan .

# For very large projects, scan incrementally
vigil scan ./packages/frontend
vigil scan ./packages/backend
```

### Slow GHSA queries

**Cause**: GitHub API rate limit (60 req/hour without token).

**Solution**:

```bash
# Generate GitHub token
# https://github.com/settings/tokens
# Scope: public_repo (read-only)

export GITHUB_TOKEN="ghp_your-token-here"
vigil scan .
```

## Output Issues

### Garbled TUI output

**Cause**: Terminal doesn't support ANSI codes.

**Solution**:

```bash
# Disable interactive TUI (future feature)
# Currently: redirect to file
vigil scan . 2>&1 | tee scan.log
```

### Unicode characters not rendering

**Cause**: Terminal encoding issue.

**Solution**:

```bash
# Set UTF-8 encoding
export LANG=en_GB.UTF-8
export LC_ALL=en_GB.UTF-8

vigil scan .
```

## Data Quality Issues

### Missing CVSS scores

**Cause**: Vulnerability not in NVD/GitHub databases yet.

**Expected**: Vigil derives CVSS from severity:
- Critical: 9.5
- High: 7.5
- Medium: 5.0
- Low: 2.5

### Incorrect severity

**Cause**: Different sources report different severities.

**Priority**: NVD > GitHub > OSV > derived

Check CVSS vector for authoritative severity assessment.

### Duplicate vulnerabilities

**Cause**: Same CVE reported with different IDs (CVE-* and GHSA-*).

**Expected**: Both IDs reference same underlying vulnerability.

## Platform-Specific Issues

### macOS: "cannot verify developer"

**Solution**:

```bash
# Build from source instead
git clone https://github.com/guttenbergovitz/vigil-cli
cd vigil-cli
go build -o vigil ./cmd/vigil
./vigil version
```

### Linux: Permission denied

**Solution**:

```bash
# Make binary executable
chmod +x vigil

# Or install to user bin
go install github.com/guttenbergovitz/vigil-cli/cmd/vigil@latest
```

### Windows: Path issues

**Solution**:

```powershell
# Add Go bin to PATH
$env:Path += ";$(go env GOPATH)\bin"

# Or use full path
& "$(go env GOPATH)\bin\vigil.exe" scan .
```

## Getting Help

Still stuck?

1. Check [Commands Reference](commands.md)
2. Review [Examples](../getting-started/examples.md)
3. Open issue: https://github.com/guttenbergovitz/vigil-cli/issues

Include:
- `vigil version` output
- `go version` output
- Full error message
- Lock file type and size
- Operating system
