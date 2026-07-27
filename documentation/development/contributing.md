# Contributing Guide

## Workflow

1. Create feature branch from `develop`
2. Write tests before code (TDD)
3. Implement feature
4. Run full test suite
5. Commit with semantic commit messages
6. Push and create PR

## Branch Naming

- `feat/description`: New feature
- `fix/description`: Bug fix
- `docs/description`: Documentation
- `test/description`: Tests
- `chore/description`: Tooling

Example: `feat/pnpm-lock-support`, `fix/osv-timeout-handling`

## Commit Discipline

Each commit should:
- Be logically self-contained
- Have passing tests
- Have clear semantic message

**Example workflow:**

```bash
# 1. Write test
git add internal/scanner/parse_test.go
git commit -m "test(scanner): add pnpm-lock parsing tests"

# 2. Implement feature
git add internal/scanner/parse.go
git commit -m "feat(scanner): parse pnpm-lock.yaml files"

# 3. Update docs
git add documentation/spec/CLI.md
git commit -m "docs(spec): add pnpm support to specification"
```

**Not allowed:**
- Mixing unrelated changes in one commit
- `git commit -m "WIP"` or `"fixes"` or `"updates"`
- Large refactors mixed with features
- Commits without passing tests

## Code Review Checklist

Before submitting PR:

- [ ] All tests pass (`go test ./...`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] No external dependencies added without ADR
- [ ] Error messages are clear and actionable
- [ ] Documentation updated if needed
- [ ] Commits are semantic and small
- [ ] No secrets, credentials, or local paths in code

## Testing Before PR

```bash
# Full test suite
go test -v ./...

# With coverage
go test -cover ./...

# Run binary manually
go build -o vigil ./cmd/vigil
./vigil scan <test-project>
```

## Documentation Expectations

If your change affects CLI behavior:
- Update `/documentation/spec/CLI.md`

If it's an architectural decision:
- Add ADR to `/documentation/adr/`

If it's a process or pattern:
- Update `/documentation/guides/DEVELOPMENT.md`

## Adding Tests

**Test file location:** Same package as code, `*_test.go` suffix.

**Minimal test example:**

```go
// internal/scanner/parse_test.go
package scanner

import "testing"

func TestParsePackageJSON(t *testing.T) {
    data := []byte(`{"name":"test"}`)
    _, err := ParsePackageJSON(data)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
}
```

**No test utils needed** until you repeat setup 3+ times.

## Dependency Changes

Adding a new external dependency requires:
1. Write ADR explaining why
2. Ensure it's in `internal/` (not exposed in `pkg/`)
3. Document in this guide
4. Get approval in PR review

**Current policy:** Stdlib first, external deps only if necessary.
