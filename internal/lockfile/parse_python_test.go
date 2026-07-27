package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseUVLock verifies parsing of uv.lock TOML file.
func TestParseUVLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "uv.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open uv.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParseUVLock(f)
	if err != nil {
		t.Fatalf("ParseUVLock returned error: %v", err)
	}

	if deps.Production["requests"] != "2.25.0" {
		t.Errorf("expected requests 2.25.0, got %s", deps.Production["requests"])
	}
	if deps.Production["urllib3"] != "1.26.4" {
		t.Errorf("expected urllib3 1.26.4, got %s", deps.Production["urllib3"])
	}
	if deps.Development["pytest"] != "6.2.2" {
		t.Errorf("expected pytest 6.2.2 in dev, got %s", deps.Development["pytest"])
	}
}

// TestParseUVLockGraph verifies graph building for uv.lock.
func TestParseUVLockGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "uv.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open uv.lock: %v", err)
	}
	defer f.Close()

	graph, err := ParseUVLockGraph(f)
	if err != nil {
		t.Fatalf("ParseUVLockGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemPyPI {
		t.Errorf("expected PyPI ecosystem, got %s", graph.Ecosystem)
	}

	reqNode := graph.Nodes["requests@2.25.0"]
	if reqNode == nil {
		t.Fatalf("requests@2.25.0 node not found in graph")
	}
	if reqNode.Ecosystem != types.EcosystemPyPI {
		t.Errorf("expected node ecosystem PyPI, got %s", reqNode.Ecosystem)
	}

	// Check child connection requests -> urllib3
	hasUrllib3 := false
	for _, child := range reqNode.Children {
		if child == "urllib3@1.26.4" {
			hasUrllib3 = true
			break
		}
	}
	if !hasUrllib3 {
		t.Errorf("expected requests to have child urllib3@1.26.4")
	}
}

// TestParsePoetryLock verifies parsing of poetry.lock TOML file.
func TestParsePoetryLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "poetry.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open poetry.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParsePoetryLock(f)
	if err != nil {
		t.Fatalf("ParsePoetryLock returned error: %v", err)
	}

	if deps.Production["jinja2"] != "2.11.2" {
		t.Errorf("expected jinja2 2.11.2, got %s", deps.Production["jinja2"])
	}
	if deps.Development["black"] != "20.8b1" {
		t.Errorf("expected black 20.8b1 in dev, got %s", deps.Development["black"])
	}
}

// TestParsePipfileLock verifies parsing of Pipfile.lock JSON file.
func TestParsePipfileLock(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "Pipfile.lock")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open Pipfile.lock: %v", err)
	}
	defer f.Close()

	deps, err := ParsePipfileLock(f)
	if err != nil {
		t.Fatalf("ParsePipfileLock returned error: %v", err)
	}

	if deps.Production["django"] != "3.2.0" {
		t.Errorf("expected django 3.2.0, got %s", deps.Production["django"])
	}
	if deps.Development["flake8"] != "3.9.0" {
		t.Errorf("expected flake8 3.9.0 in dev, got %s", deps.Development["flake8"])
	}
}

// TestParseRequirementsTxt verifies parsing of requirements.txt text file.
func TestParseRequirementsTxt(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "python", "requirements.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open requirements.txt: %v", err)
	}
	defer f.Close()

	deps, err := ParseRequirementsTxt(f)
	if err != nil {
		t.Fatalf("ParseRequirementsTxt returned error: %v", err)
	}

	if deps.Production["requests"] != "2.25.0" {
		t.Errorf("expected requests 2.25.0, got %s", deps.Production["requests"])
	}
	if deps.Production["urllib3"] != "1.26.4" {
		t.Errorf("expected urllib3 1.26.4, got %s", deps.Production["urllib3"])
	}
	if deps.Production["flask"] != "2.0.1" {
		t.Errorf("expected flask 2.0.1, got %s", deps.Production["flask"])
	}
	if deps.Production["gunicorn"] != "20.1.0" {
		t.Errorf("expected gunicorn 20.1.0, got %s", deps.Production["gunicorn"])
	}
}
