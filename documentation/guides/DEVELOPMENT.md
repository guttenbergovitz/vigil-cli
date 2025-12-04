# Development Guide

## Setup

### Requirements
- Go 1.25+
- `git`

### Initial Setup

```bash
git clone <repo>
cd vigil-cli
go mod tidy
```

## Building

```bash
# Build binary
go build -o vigil ./cmd/vigil

# Or with specific output
go build -o bin/vigil ./cmd/vigil
```

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/scanner

# Run with verbose output
go test -v ./...
```

**Test files:** Colocated with code as `*_test.go` files.

## Code Organization

### cmd/vigil/
Main entry point. Should contain only:
- Flag parsing
- Input validation
- Orchestration of internal packages
- Error handling and exit codes

Minimal business logic—delegate to `internal/`.

### internal/scanner/
Package tree analysis and lock file parsing.

**Responsibilities:**
- Parse `package.json`
- Parse lock files (npm, Yarn, pnpm)
- Build dependency tree
- Classify as production or development

**No external dependencies** to OSV or reporting—pure dependency analysis.

### internal/osv/
OSV API client.

**Responsibilities:**
- HTTP requests to OSV API
- Request/response marshaling
- Error handling and retries
- Timeout management

**Idempotent**: Same request should return same result.

### internal/report/
Report generation from scan cache.

**Responsibilities:**
- Load `.vigil.cache`
- Filter vulnerabilities by severity, type
- Pass formatted data to exporters

### pkg/config/
Configuration file parsing (`.vigil.toml`).

**Responsibilities:**
- Read and unmarshal TOML
- Validate configuration
- Return config struct

### pkg/models/
Shared data structures.

**Examples:**
- `Dependency`
- `Vulnerability`
- `ScanResult`
- `Config`

**Rule:** If multiple packages use it, it belongs in `models`.

### pkg/export/
Export formatters.

**Responsibilities:**
- CSV export
- Markdown export
- JSON export

**Signature:**
```go
func ExportCSV(results *models.ScanResult, writer io.Writer) error
func ExportMarkdown(results *models.ScanResult, writer io.Writer) error
```

## Naming Conventions

### Go Idioms
- Interfaces: `Reader`, `Writer`, `Handler` (not `IReader`)
- Errors: `var ErrInvalidConfig = errors.New("invalid config")`
- Functions: lowercase with verb: `parseLockFile()`, `queryOSV()`
- Constants: `UPPERCASE` for public, `lowercase` for internal
- Packages: lowercase, single word if possible (e.g., `scanner`, not `depScanner`)

### Files
- `*_test.go` for tests
- No helpers files—use logical packages
- `types.go` for type definitions if needed

## Commit Messages

Use semantic commit format:

```
type(scope): description

[optional body]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Tests
- `refactor`: Code reorganization (no behavior change)
- `chore`: Tooling, dependencies, non-functional

**Examples:**
```
feat(scanner): parse pnpm-lock.yaml

Add support for pnpm lock files in dependency tree analysis.

feat(osv): add retry logic for API failures
fix(report): handle empty vulnerability list
docs(adr): add caching strategy decision record
test(scanner): add lock file parsing tests
```

**No author attribution in commits.** Message should speak for itself.

## Error Handling

### Patterns

**Return early:**
```go
func scan(path string) error {
    lockFile, err := findLockFile(path)
    if err != nil {
        return fmt.Errorf("find lock file: %w", err)
    }

    deps, err := parseLockFile(lockFile)
    if err != nil {
        return fmt.Errorf("parse lock file: %w", err)
    }
}
```

**Wrap errors with context:**
```go
return fmt.Errorf("scan %s: %w", path, err)
```

**Don't log and return:**
```go
// Bad
log.Fatalf("error: %v", err)

// Good
return fmt.Errorf("scan failed: %w", err)
```

### Exit Codes
- `0`: Success
- `1`: Vulnerabilities found (business logic)
- `2`: Error (missing file, API failure, etc.)

## Testing Strategy

### Unit Tests

Test single functions in isolation:

```go
func TestParsePackageJSON(t *testing.T) {
    data := []byte(`{"name":"test","version":"1.0.0"}`)
    pkg, err := ParsePackageJSON(data)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if pkg.Name != "test" {
        t.Errorf("want name=test, got %s", pkg.Name)
    }
}
```

### Table-Driven Tests

For multiple input scenarios:

```go
func TestRiskScore(t *testing.T) {
    tests := []struct {
        name     string
        severity string
        inProd   bool
        want     int
    }{
        {"critical in prod", "critical", true, 100},
        {"low in dev", "low", false, 10},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := CalcRiskScore(tt.severity, tt.inProd)
            if got != tt.want {
                t.Errorf("want %d, got %d", tt.want, got)
            }
        })
    }
}
```

### Integration Tests

In `tests/` directory for end-to-end workflows:

```go
// tests/integration_test.go
func TestFullScan(t *testing.T) {
    tmpdir := t.TempDir()
    // Copy test project
    // Run vigil scan
    // Verify output
}
```

## Debugging

### Print debugging
```go
fmt.Printf("DEBUG: value=%v\n", value)
```

### Running single test
```bash
go test -run TestParsePackageJSON ./internal/scanner
```

### Detailed trace
```bash
go test -v -run TestParsePackageJSON ./internal/scanner
```

## Adding Dependencies

**Constraint:** Minimize external dependencies. Use Go stdlib first.

If adding a dependency:

1. Justify in an ADR
2. Choose only if stdlib insufficient
3. Update `go.mod` and `go.sum`
4. Document in DEPENDENCIES.md (if added)

Current approach: No external deps in core packages (aim for stdlib only).

## Linting and Formatting

```bash
# Format code
go fmt ./...

# Lint with golangci-lint (if installed)
golangci-lint run ./...

# Simple vet
go vet ./...
```

**No strict linting configuration yet**—use Go conventions.
