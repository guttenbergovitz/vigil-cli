# Testing Guide

Running and writing tests for Vigil.

## Running Tests

### All Tests

```bash
go test ./...
```

### Specific Package

```bash
go test ./internal/lockfile
go test ./internal/osv
go test ./internal/report
```

### Verbose Output

```bash
go test -v ./...
```

### With Coverage

```bash
go test -cover ./...

# Detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Test Structure

### Unit Tests

Located alongside source files:

```
internal/lockfile/
├── parse.go
├── parse_test.go          # Unit tests for parse.go
├── cache.go
└── cache_test.go          # Unit tests for cache.go
```

### Test Naming

```go
func TestFunctionName(t *testing.T)           // Basic test
func TestFunctionName_EdgeCase(t *testing.T)  // Specific scenario
```

### Table-driven Tests

```go
func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected types.Severity
		ok       bool
	}{
		{"low", "low", types.Low, true},
		{"high", "high", types.High, true},
		{"invalid", "invalid", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := types.ParseSeverity(tt.input)
			if ok != tt.ok {
				t.Errorf("expected ok=%v, got %v", tt.ok, ok)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
```

## Testing Practices

### No Mocks for API Clients

Tests use real network calls for accuracy:

```go
func TestOSVQuery(t *testing.T) {
	client := osv.New("https://api.osv.dev/v1/query", 10)
	vulns, err := client.Query("lodash", "4.17.20")
	// Real API call, verifies actual response format
}
```

**Why**: Ensures compatibility with actual APIs.

**Trade-off**: Tests require network, slower.

### Test Data

Use real-world examples:

```go
// test-project/ contains actual lock files for testing
func TestParsePnpmLock(t *testing.T) {
	f, _ := os.Open("../../test-project/pnpm-lock.yaml")
	graph, err := lockfile.ParsePnpmLockGraph(f)
	// Test against real pnpm lock file
}
```

### Error Cases

Test both success and failure paths:

```go
func TestHashFile(t *testing.T) {
	// Success case
	hash, err := HashFile("testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}

	// Error case
	_, err = HashFile("nonexistent.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
```

## Writing New Tests

### 1. Create Test File

```bash
# For new source file
touch internal/mypackage/myfile.go
touch internal/mypackage/myfile_test.go
```

### 2. Basic Test Template

```go
package mypackage

import "testing"

func TestMyFunction(t *testing.T) {
	result := MyFunction("input")
	expected := "expected output"

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}
```

### 3. Run and Iterate

```bash
go test -v ./internal/mypackage
```

## Integration Testing

End-to-end workflow tests:

```go
func TestScanWorkflow(t *testing.T) {
	// 1. Scan
	result, err := scan.Scan("/path/to/test-project", ...)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Verify results
	if result.TotalVulns == 0 {
		t.Error("expected vulnerabilities")
	}

	// 3. Generate report
	var buf bytes.Buffer
	report.Table(result, &buf)

	// 4. Verify output
	output := buf.String()
	if !strings.Contains(output, "SUMMARY") {
		t.Error("missing summary in output")
	}
}
```

## Performance Testing

Benchmark critical paths:

```go
func BenchmarkParsePnpmLock(b *testing.B) {
	data, _ := os.ReadFile("testdata/large-pnpm-lock.yaml")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lockfile.ParsePnpmLockGraph(bytes.NewReader(data))
	}
}
```

Run benchmarks:

```bash
go test -bench=. ./internal/lockfile
```

## Test Coverage Goals

- **Parsers**: >80% (complex logic)
- **API clients**: >60% (network dependent)
- **Report formatters**: >70% (output validation)
- **Overall**: >65%

Check coverage:

```bash
go test -cover ./...
```

## Continuous Integration

Tests run automatically on:
- Push to any branch
- Pull request creation
- Pre-merge checks

See `.github/workflows/` for CI configuration.

## Troubleshooting Tests

### "connection refused" in API tests

Network issue or API down. Tests assume internet connectivity.

### "invalid JSON" in parser tests

Test data may be outdated. Regenerate test fixtures:

```bash
cd test-project
npm install  # or yarn/pnpm
```

### Flaky tests

API rate limiting can cause intermittent failures. Add delays:

```go
time.Sleep(100 * time.Millisecond)
```

## Next Steps

- [Setup](setup.md) - Development environment
- [Contributing](contributing.md) - Contribution guidelines
- [Components](../architecture/components.md) - Code structure
