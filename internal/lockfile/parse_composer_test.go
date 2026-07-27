package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseComposerLock verifies parsing of PHP composer.lock JSON file.
func TestParseComposerLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "php", "composer.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open composer.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParseComposerLock(f)
	if err != nil {
		t.Fatalf("ParseComposerLock returned error: %v", err)
	}

	if deps.Production["guzzlehttp/guzzle"] != "7.3.0" {
		t.Errorf("expected guzzlehttp/guzzle 7.3.0, got %s", deps.Production["guzzlehttp/guzzle"])
	}
	if deps.Production["guzzlehttp/promises"] != "1.4.1" {
		t.Errorf("expected guzzlehttp/promises 1.4.1, got %s", deps.Production["guzzlehttp/promises"])
	}
	if deps.Development["phpunit/phpunit"] != "9.5.0" {
		t.Errorf("expected phpunit/phpunit 9.5.0 in dev, got %s", deps.Development["phpunit/phpunit"])
	}
}

// TestParseComposerLockGraph verifies graph building for PHP composer.lock.
func TestParseComposerLockGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "php", "composer.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open composer.lock: %v", err)
	}
	defer f.Close()

	graph, err := ParseComposerLockGraph(f)
	if err != nil {
		t.Fatalf("ParseComposerLockGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemPackagist {
		t.Errorf("expected Packagist ecosystem, got %s", graph.Ecosystem)
	}

	guzzleNode := graph.Nodes["guzzlehttp/guzzle@7.3.0"]
	if guzzleNode == nil {
		t.Fatalf("guzzlehttp/guzzle@7.3.0 node not found in graph")
	}
	if guzzleNode.Ecosystem != types.EcosystemPackagist {
		t.Errorf("expected node ecosystem Packagist, got %s", guzzleNode.Ecosystem)
	}

	// Verify child connections for guzzle -> promises
	hasPromises := false
	for _, child := range guzzleNode.Children {
		if child == "guzzlehttp/promises@1.4.1" {
			hasPromises = true
			break
		}
	}
	if !hasPromises {
		t.Errorf("expected guzzlehttp/guzzle to have child guzzlehttp/promises@1.4.1")
	}
}
