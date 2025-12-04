# Vigil CLI

Lightweight vulnerability scanner for JavaScript/TypeScript projects. Analyzes dependency trees and reports CVE exposure with context.

## Quick Start

```bash
vigil scan <path>
vigil report
```

## Structure

```
.
├── cmd/               # CLI entry points
├── internal/          # Private application code
│   ├── scanner/       # Dependency tree analysis
│   ├── report/        # Report generation
│   └── osv/           # OSV API integration
├── pkg/               # Public libraries
│   ├── config/        # Configuration handling
│   ├── models/        # Data structures
│   └── export/        # CSV, Markdown export
├── documentation/     # All docs
│   ├── adr/           # Architecture decisions
│   ├── spec/          # Technical specification
│   ├── guides/        # Developer guidelines
│   └── miss/          # Temporary notes
└── tests/             # Test suite
```

## Building

```bash
go build -o vigil ./cmd/vigil
```

## Requirements

- Go 1.25+
- No external binary dependencies
