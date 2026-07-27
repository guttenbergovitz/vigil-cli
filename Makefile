.PHONY: build install test clean version tag

# Get version from git
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Linker flags to inject version
LDFLAGS := -ldflags "\
	-X github.com/guttenbergovitz/vigil-cli/internal/version.Version=$(VERSION) \
	-X github.com/guttenbergovitz/vigil-cli/internal/version.Commit=$(COMMIT) \
	-X github.com/guttenbergovitz/vigil-cli/internal/version.Date=$(DATE)"

# Build binary
build:
	go build $(LDFLAGS) -o vigil ./cmd/vigil

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/vigil

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f vigil

# Show current version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

# Create a new git tag (usage: make tag VERSION=v1.0.0)
tag:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make tag VERSION=v1.0.0"; \
		exit 1; \
	fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Created tag $(VERSION)"
	@echo "Push with: git push origin $(VERSION)"
