package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseCargoLock verifies parsing of Rust Cargo.lock TOML file.
func TestParseCargoLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "rust", "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Cargo.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParseCargoLock(f)
	if err != nil {
		t.Fatalf("ParseCargoLock returned error: %v", err)
	}

	if deps.Production["smallvec"] != "1.6.0" {
		t.Errorf("expected smallvec 1.6.0, got %s", deps.Production["smallvec"])
	}
	if deps.Production["tokio"] != "1.8.0" {
		t.Errorf("expected tokio 1.8.0, got %s", deps.Production["tokio"])
	}
	if deps.Production["bytes"] != "1.0.1" {
		t.Errorf("expected bytes 1.0.1, got %s", deps.Production["bytes"])
	}
}

// TestParseCargoLockGraph verifies graph building for Rust Cargo.lock.
func TestParseCargoLockGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "rust", "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Cargo.lock: %v", err)
	}
	defer f.Close()

	graph, err := ParseCargoLockGraph(f)
	if err != nil {
		t.Fatalf("ParseCargoLockGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemCargo {
		t.Errorf("expected Cargo ecosystem, got %s", graph.Ecosystem)
	}

	tokioNode := graph.Nodes["tokio@1.8.0"]
	if tokioNode == nil {
		t.Fatalf("tokio@1.8.0 node not found in graph")
	}
	if tokioNode.Ecosystem != types.EcosystemCargo {
		t.Errorf("expected node ecosystem Cargo, got %s", tokioNode.Ecosystem)
	}

	// Verify child connections for tokio -> bytes
	hasBytes := false
	for _, child := range tokioNode.Children {
		if child == "bytes@1.0.1" {
			hasBytes = true
			break
		}
	}
	if !hasBytes {
		t.Errorf("expected tokio to have child bytes@1.0.1")
	}
}
