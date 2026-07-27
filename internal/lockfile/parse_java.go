package lockfile

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var propertyRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// ParsePomXml parses Maven pom.xml XML build file.
func ParsePomXml(r io.Reader) (*Dependencies, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read pom.xml: %w", err)
	}

	// 1. Extract properties map
	props := extractPomProperties(data)

	// 2. Decode POM structure
	type dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}

	type pom struct {
		Dependencies []dependency `xml:"dependencies>dependency"`
	}

	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal pom.xml: %w", err)
	}

	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	for _, dep := range p.Dependencies {
		groupID := strings.TrimSpace(dep.GroupID)
		artifactID := strings.TrimSpace(dep.ArtifactID)
		version := strings.TrimSpace(dep.Version)
		scope := strings.TrimSpace(strings.ToLower(dep.Scope))

		if groupID == "" || artifactID == "" {
			continue
		}

		// Resolve ${property.name} references
		version = resolvePomProperty(version, props)
		if version == "" {
			continue
		}

		pkgName := groupID + ":" + artifactID

		if scope == "test" {
			deps.Development[pkgName] = version
		} else {
			deps.Production[pkgName] = version
		}
	}

	return deps, nil
}

// ParseGradleLockfile parses Gradle gradle.lockfile format.
func ParseGradleLockfile(r io.Reader) (*Dependencies, error) {
	deps := &Dependencies{
		Production:  make(map[string]string),
		Development: make(map[string]string),
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: group:artifact:version=classpaths
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 1 {
			continue
		}

		gav := strings.TrimSpace(parts[0])
		classpaths := ""
		if len(parts) == 2 {
			classpaths = strings.ToLower(parts[1])
		}

		gavParts := strings.Split(gav, ":")
		if len(gavParts) < 3 {
			continue
		}

		groupID := gavParts[0]
		artifactID := gavParts[1]
		version := gavParts[2]

		pkgName := groupID + ":" + artifactID

		isDev := false
		if classpaths != "" {
			isDev = true
			for _, cp := range strings.Split(classpaths, ",") {
				cp = strings.TrimSpace(cp)
				if !strings.HasPrefix(cp, "test") {
					isDev = false
					break
				}
			}
		}

		if isDev {
			deps.Development[pkgName] = version
		} else {
			deps.Production[pkgName] = version
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read gradle.lockfile: %w", err)
	}

	return deps, nil
}

func extractPomProperties(data []byte) map[string]string {
	props := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	inProperties := false
	var currentPropName string

	for {
		token, err := decoder.Token()
		if err != nil || token == nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "properties" {
				inProperties = true
			} else if inProperties {
				currentPropName = t.Name.Local
			}
		case xml.EndElement:
			if t.Name.Local == "properties" {
				inProperties = false
			} else if inProperties {
				currentPropName = ""
			}
		case xml.CharData:
			if inProperties && currentPropName != "" {
				val := strings.TrimSpace(string(t))
				if val != "" {
					props[currentPropName] = val
				}
			}
		}
	}

	return props
}

func resolvePomProperty(val string, props map[string]string) string {
	matches := propertyRegex.FindAllStringSubmatch(val, -1)
	resolved := val
	for _, match := range matches {
		if len(match) == 2 {
			propKey := match[1]
			if propVal, ok := props[propKey]; ok {
				resolved = strings.ReplaceAll(resolved, match[0], propVal)
			}
		}
	}
	return resolved
}
