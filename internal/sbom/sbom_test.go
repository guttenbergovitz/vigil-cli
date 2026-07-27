package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

func createSampleGraph() (*types.ScanResult, *types.DependencyGraph) {
	graph := types.NewDependencyGraph()
	graph.Ecosystem = types.EcosystemNPM
	graph.AddNode("express", "4.18.2", types.Production, true)
	graph.AddNode("body-parser", "1.19.0", types.Production, false)
	graph.AddEdge("express@4.18.2", "body-parser@1.19.0")

	result := &types.ScanResult{
		Version:     1,
		ProjectPath: "/app",
		ScannedAt:   time.Now().UTC(),
		LockFile:    "package-lock.json",
		Dependencies: []types.Dependency{
			{Name: "express", Version: "4.18.2", Type: types.Production, Ecosystem: types.EcosystemNPM},
			{Name: "body-parser", Version: "1.19.0", Type: types.Production, Ecosystem: types.EcosystemNPM},
		},
	}

	return result, graph
}

// TestGenerateCycloneDX verifies valid CycloneDX v1.5 JSON output.
func TestGenerateCycloneDX(t *testing.T) {
	result, graph := createSampleGraph()
	var buf bytes.Buffer

	err := GenerateCycloneDX(result, graph, &buf)
	if err != nil {
		t.Fatalf("GenerateCycloneDX returned error: %v", err)
	}

	var jsonOut map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonOut); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if jsonOut["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", jsonOut["bomFormat"])
	}
	if jsonOut["specVersion"] != "1.5" {
		t.Errorf("expected specVersion 1.5, got %v", jsonOut["specVersion"])
	}

	components, ok := jsonOut["components"].([]interface{})
	if !ok || len(components) != 2 {
		t.Fatalf("expected 2 components in CycloneDX output, got %v", jsonOut["components"])
	}
}

// TestGenerateSPDX verifies valid SPDX v2.3 JSON output.
func TestGenerateSPDX(t *testing.T) {
	result, graph := createSampleGraph()
	var buf bytes.Buffer

	err := GenerateSPDX(result, graph, &buf)
	if err != nil {
		t.Fatalf("GenerateSPDX returned error: %v", err)
	}

	var jsonOut map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonOut); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if jsonOut["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("expected spdxVersion SPDX-2.3, got %v", jsonOut["spdxVersion"])
	}

	packages, ok := jsonOut["packages"].([]interface{})
	if !ok || len(packages) != 2 {
		t.Fatalf("expected 2 packages in SPDX output, got %v", jsonOut["packages"])
	}

	bufStr := buf.String()
	if !strings.Contains(bufStr, "pkg:npm/express@4.18.2") {
		t.Errorf("expected PURL in SPDX output")
	}
}
