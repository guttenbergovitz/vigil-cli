package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestParseGoMod verifies parsing of Go go.mod file.
func TestParseGoMod(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "go", "go.mod")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open go.mod: %v", err)
	}
	defer f.Close()

	deps, err := ParseGoMod(f)
	if err != nil {
		t.Fatalf("ParseGoMod returned error: %v", err)
	}

	if deps.Production["github.com/gin-gonic/gin"] != "v1.7.0" {
		t.Errorf("expected gin v1.7.0, got %s", deps.Production["github.com/gin-gonic/gin"])
	}
	if deps.Production["github.com/gofiber/fiber/v2"] != "v2.20.0" {
		t.Errorf("expected fiber v2.20.0, got %s", deps.Production["github.com/gofiber/fiber/v2"])
	}
	if deps.Development["github.com/valyala/fasthttp"] != "v1.30.0" {
		t.Errorf("expected fasthttp v1.30.0 in dev, got %s", deps.Development["github.com/valyala/fasthttp"])
	}
}

// TestParseGoModGraph verifies graph building for Go go.mod.
func TestParseGoModGraph(t *testing.T) {
	path := filepath.Join("..", "..", "test-project", "go", "go.mod")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open go.mod: %v", err)
	}
	defer f.Close()

	graph, err := ParseGoModGraph(f)
	if err != nil {
		t.Fatalf("ParseGoModGraph returned error: %v", err)
	}

	if graph.Ecosystem != types.EcosystemGo {
		t.Errorf("expected Go ecosystem, got %s", graph.Ecosystem)
	}

	ginNode := graph.Nodes["github.com/gin-gonic/gin@v1.7.0"]
	if ginNode == nil {
		t.Fatalf("github.com/gin-gonic/gin@v1.7.0 node not found in graph")
	}
	if ginNode.Ecosystem != types.EcosystemGo {
		t.Errorf("expected node ecosystem Go, got %s", ginNode.Ecosystem)
	}
}
