package lockfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParsePomXml verifies parsing of Maven pom.xml.
func TestParsePomXml(t *testing.T) {
	pomPath := filepath.Join("..", "..", "test-project", "java", "pom.xml")
	file, err := os.Open(pomPath)
	if err != nil {
		t.Fatalf("failed to open pom.xml: %v", err)
	}
	defer file.Close()

	deps, err := ParsePomXml(file)
	if err != nil {
		t.Fatalf("ParsePomXml returned error: %v", err)
	}

	if len(deps.Production) != 2 {
		t.Errorf("expected 2 production dependencies in pom.xml, got %d", len(deps.Production))
	}
	if len(deps.Development) != 1 {
		t.Errorf("expected 1 dev dependency in pom.xml, got %d", len(deps.Development))
	}

	if version, ok := deps.Production["org.apache.logging.log4j:log4j-core"]; !ok || version != "2.14.1" {
		t.Errorf("expected log4j-core version 2.14.1, got %q", version)
	}

	if version, ok := deps.Production["org.springframework:spring-core"]; !ok || version != "5.3.20" {
		t.Errorf("expected spring-core version 5.3.20, got %q", version)
	}

	if version, ok := deps.Development["junit:junit"]; !ok || version != "4.13.2" {
		t.Errorf("expected junit version 4.13.2, got %q", version)
	}
}

// TestParseGradleLockfile verifies parsing of gradle.lockfile.
func TestParseGradleLockfile(t *testing.T) {
	gradlePath := filepath.Join("..", "..", "test-project", "java", "gradle.lockfile")
	file, err := os.Open(gradlePath)
	if err != nil {
		t.Fatalf("failed to open gradle.lockfile: %v", err)
	}
	defer file.Close()

	deps, err := ParseGradleLockfile(file)
	if err != nil {
		t.Fatalf("ParseGradleLockfile returned error: %v", err)
	}

	if len(deps.Production) != 2 {
		t.Errorf("expected 2 production dependencies in gradle.lockfile, got %d", len(deps.Production))
	}
	if len(deps.Development) != 1 {
		t.Errorf("expected 1 dev dependency in gradle.lockfile, got %d", len(deps.Development))
	}

	if version, ok := deps.Production["org.apache.logging.log4j:log4j-core"]; !ok || version != "2.14.1" {
		t.Errorf("expected log4j-core version 2.14.1, got %q", version)
	}
}
