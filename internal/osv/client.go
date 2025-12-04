package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// Client provides access to OSV API.
type Client struct {
	endpoint string
	timeout  int
	httpClient *http.Client
}

// New creates a new OSV client with given endpoint and timeout.
func New(endpoint string, timeout int) *Client {
	return &Client{
		endpoint: endpoint,
		timeout:  timeout,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

// QueryRequest represents a request to OSV API.
type QueryRequest struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
}

// QueryResponse represents the OSV API response.
type QueryResponse struct {
	Vulns []struct {
		ID        string        `json:"id"`
		Summary   string        `json:"summary"`
		Details   string        `json:"details"`
		Severity  interface{}   `json:"severity"` // Can be string, array, or object
		Published string        `json:"published"`
		Modified  string        `json:"modified"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		DatabaseSpecific interface{} `json:"database_specific"` // Contains CVSS info
		// For NVD/CVE data
		CVSSv3 *struct {
			Score      float64 `json:"score"`
			Vector     string  `json:"vectorString"`
			BaseScore  float64 `json:"baseScore"`
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssv3"`
		CVSSv2 *struct {
			Score float64 `json:"score"`
		} `json:"cvssv2"`
	} `json:"vulns"`
}

// Query retrieves vulnerabilities for a package from OSV API.
func (c *Client) Query(pkg, version string) ([]models.Vulnerability, error) {
	req := QueryRequest{}
	// Build PURL - handle scoped packages (@scope/name)
	// PURL format: pkg:npm/%40scope/name@version (@ encoded as %40)
	purl := pkg
	if strings.HasPrefix(pkg, "@") {
		// Scoped package - @ in scope part needs encoding in PURL
		purl = strings.ReplaceAll(pkg, "@", "%40")
	}
	req.Package.PURL = fmt.Sprintf("pkg:npm/%s@%s", purl, version)

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.endpoint,
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("query OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API error: %d %s", resp.StatusCode, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var vulns []models.Vulnerability
	for _, v := range queryResp.Vulns {
		// Extract severity - can be string, array, or object
		sev := extractSeverity(v.Severity)
		if sev == "" {
			sev = models.Medium
		}

		// Extract CVSS score
		var cvssScore float64
		if v.CVSSv3 != nil && v.CVSSv3.Score > 0 {
			cvssScore = v.CVSSv3.Score
		} else if v.CVSSv2 != nil && v.CVSSv2.Score > 0 {
			cvssScore = v.CVSSv2.Score
		}

		var published, modified *time.Time
		if v.Published != "" {
			if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
				published = &t
			}
		}
		if v.Modified != "" {
			if t, err := time.Parse(time.RFC3339, v.Modified); err == nil {
				modified = &t
			}
		}

		refs := make([]string, len(v.References))
		for i, ref := range v.References {
			refs[i] = ref.URL
		}

		vuln := models.Vulnerability{
			ID:          v.ID,
			Summary:     v.Summary,
			Description: v.Details,
			Severity:    sev,
			CVSSScore:   cvssScore,
			References:  refs,
			PublishedAt: published,
			ModifiedAt:  modified,
			Sources:     []string{"osv"},
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// BatchQuery queries multiple packages and returns vulnerabilities indexed by package@version.
func (c *Client) BatchQuery(pkgs []struct {
	name    string
	version string
}) (map[string][]models.Vulnerability, error) {
	results := make(map[string][]models.Vulnerability)

	for _, pkg := range pkgs {
		key := fmt.Sprintf("%s@%s", pkg.name, pkg.version)
		vulns, err := c.Query(pkg.name, pkg.version)
		if err != nil {
			// Continue on error, mark as empty but don't fail
			vulns = []models.Vulnerability{}
		}
		results[key] = vulns
	}

	return results, nil
}

// CalculateRiskScore computes a risk score based on severity and context.
// Returns a value 0-100.
func CalculateRiskScore(severity models.Severity, inProduction bool) int {
	return CalculateRiskScoreWithDepth(severity, inProduction, 0)
}

// CalculateRiskScoreWithDepth computes risk score with supply chain depth modifier.
// depth: 0 = direct, 1 = transitive (1 level), 2 = deeper, etc.
func CalculateRiskScoreWithDepth(severity models.Severity, inProduction bool, depth int) int {
	baseScore := map[models.Severity]int{
		models.Critical: 90,
		models.High:     70,
		models.Medium:   50,
		models.Low:      20,
	}

	score := baseScore[severity]
	if score == 0 {
		score = 50 // default for unknown severity
	}

	// Boost score if in production
	if inProduction {
		score = (score * 110) / 100
		if score > 100 {
			score = 100
		}
	} else {
		// Reduce score if only in development
		score = (score * 60) / 100
	}

	// Supply chain modifier: reduce score for deeper transitive deps
	// Direct (depth 0): no change
	// Transitive (depth 1+): reduce by 10% per level
	if depth > 0 {
		reduction := 10 * depth
		if reduction > 40 {
			reduction = 40 // cap at 40% reduction
		}
		score = (score * (100 - reduction)) / 100
	}

	return score
}

// ScanGraphVulnerabilities scans all nodes in dependency graph against OSV API.
func (c *Client) ScanGraphVulnerabilities(graph *models.DependencyGraph) error {
	for _, node := range graph.Nodes {
		vulns, err := c.Query(node.Name, node.Version)
		if err != nil {
			// Log but continue
			continue
		}

		// Calculate risk scores with depth modifier
		for i := range vulns {
			vulns[i].RiskScore = CalculateRiskScoreWithDepth(
				vulns[i].Severity,
				node.Type == models.Production,
				node.Depth,
			)
		}

		// Store vulnerabilities in node
		node.Vulnerabilities = vulns
	}

	return nil
}

// extractSeverity handles different severity formats from OSV API:
// - string: "high"
// - array: ["high"]
// - object: {"cvssv3": {...}}
func extractSeverity(sev interface{}) models.Severity {
	if sev == nil {
		return ""
	}

	switch v := sev.(type) {
	case string:
		// Direct string value
		return models.Severity(v)
	case []interface{}:
		// Array - take first element
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return models.Severity(str)
			}
		}
	case map[string]interface{}:
		// Object - try to extract from common fields
		if cvss, ok := v["cvssv3"]; ok {
			if cvssObj, ok := cvss.(map[string]interface{}); ok {
				if severity, ok := cvssObj["severity"].(string); ok {
					return models.Severity(severity)
				}
			}
		}
		if cvss, ok := v["cvssv2"]; ok {
			if cvssObj, ok := cvss.(map[string]interface{}); ok {
				if severity, ok := cvssObj["severity"].(string); ok {
					return models.Severity(severity)
				}
			}
		}
	}

	return ""
}
