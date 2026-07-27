package lockfile

import (
	"os"
	"testing"
)

func TestParseNPMLockGraph(t *testing.T) {
	f, err := os.Open("../../test-project/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	graph, err := ParseNPMLockGraph(f)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(graph.Nodes) == 0 {
		t.Error("expected nodes, got 0")
	}

	if len(graph.Root) == 0 {
		t.Error("expected root dependencies, got 0")
	}

	// Check if express node exists
	expressKey := "express@4.18.2"
	express, ok := graph.Nodes[expressKey]
	if !ok {
		t.Errorf("expected express@4.18.2 node, not found")
	} else {
		// Express should have children (body-parser, debug, qs, etc)
		if len(express.Children) == 0 {
			t.Error("express should have children dependencies")
		}
		t.Logf("Express has %d children", len(express.Children))
	}

	// Check if body-parser exists and has express as parent
	bodyParserKey := "body-parser@1.20.1"
	bodyParser, ok := graph.Nodes[bodyParserKey]
	if !ok {
		t.Errorf("expected body-parser@1.20.1 node, not found")
	} else {
		// Body-parser should have express as parent
		hasExpressParent := false
		for _, parent := range bodyParser.Parents {
			if parent == expressKey {
				hasExpressParent = true
				break
			}
		}
		if !hasExpressParent {
			t.Error("body-parser should have express as parent")
		}
	}

	// Check dependency path
	path := graph.GetVulnerablePath(bodyParserKey)
	t.Logf("Path to body-parser: %v", path)
	if len(path) < 2 {
		t.Error("path should have at least 2 nodes (express -> body-parser)")
	}
}

func TestParseYarnLockGraph(t *testing.T) {
	f, err := os.Open("../../test-project/yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	graph, err := ParseYarnLockGraph(f)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(graph.Nodes) == 0 {
		t.Error("expected nodes, got 0")
	}

	if len(graph.Root) == 0 {
		t.Error("expected root dependencies, got 0")
	}

	// Check if express node exists
	expressKey := "express@4.18.2"
	express, ok := graph.Nodes[expressKey]
	if !ok {
		t.Errorf("expected express@4.18.2 node, not found")
	} else {
		// Express should have children (body-parser, debug, qs)
		if len(express.Children) == 0 {
			t.Error("express should have children dependencies")
		}
		t.Logf("Express has %d children", len(express.Children))
	}

	// Check if body-parser exists and has express as parent
	bodyParserKey := "body-parser@1.20.1"
	bodyParser, ok := graph.Nodes[bodyParserKey]
	if !ok {
		t.Errorf("expected body-parser@1.20.1 node, not found")
	} else {
		// Body-parser should have express as parent
		hasExpressParent := false
		for _, parent := range bodyParser.Parents {
			if parent == expressKey {
				hasExpressParent = true
				break
			}
		}
		if !hasExpressParent {
			t.Error("body-parser should have express as parent")
		}
	}

	// Check dependency path
	path := graph.GetVulnerablePath(bodyParserKey)
	t.Logf("Path to body-parser: %v", path)
	if len(path) < 2 {
		t.Error("path should have at least 2 nodes (express -> body-parser)")
	}
}
