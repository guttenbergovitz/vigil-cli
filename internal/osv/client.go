package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
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

// Query retrieves vulnerabilities for an npm package from OSV API.
func (c *Client) Query(pkg, version string) ([]types.Vulnerability, error) {
	return c.QueryWithEcosystem(pkg, version, types.EcosystemNPM)
}

// QueryWithEcosystem retrieves vulnerabilities for a package in a given ecosystem from OSV API.
func (c *Client) QueryWithEcosystem(pkg, version string, ecosystem types.Ecosystem) ([]types.Vulnerability, error) {
	req := QueryRequest{}
	
	purlType := "npm"
	switch ecosystem {
	case types.EcosystemPyPI:
		purlType = "pypi"
	case types.EcosystemGo:
		purlType = "golang"
	case types.EcosystemCargo:
		purlType = "cargo"
	case types.EcosystemPackagist:
		purlType = "composer"
	case types.EcosystemMaven:
		purlType = "maven"
	default:
		purlType = "npm"
	}

	// Build PURL - handle scoped packages (@scope/name)
	purl := pkg
	if strings.HasPrefix(pkg, "@") {
		// Scoped package - @ in scope part needs encoding in PURL
		purl = strings.ReplaceAll(pkg, "@", "%40")
	}
	req.Package.PURL = fmt.Sprintf("pkg:%s/%s@%s", purlType, purl, version)

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

	var vulns []types.Vulnerability
	for _, v := range queryResp.Vulns {
		// Extract severity with fallback to CVSS BaseSeverity
		sev := extractSeverity(v.Severity)
		if sev == "" && v.CVSSv3 != nil && v.CVSSv3.BaseSeverity != "" {
			sev = types.Severity(strings.ToLower(v.CVSSv3.BaseSeverity))
		}
		if sev == "" && v.CVSSv2 != nil && v.CVSSv2.Score > 0 {
			// Derive severity from CVSS v2 score
			sev = deriveSeverityFromCVSSv2(v.CVSSv2.Score)
		}
		if sev == "" {
			sev = types.Medium
		}

		// Extract CVSS score - try cvssv3 first, then cvssv2, then database_specific
		var cvssScore float64
		var cvssVector string
		if v.CVSSv3 != nil {
			// Try Score first, then BaseScore
			if v.CVSSv3.Score > 0 {
				cvssScore = v.CVSSv3.Score
			} else if v.CVSSv3.BaseScore > 0 {
				cvssScore = v.CVSSv3.BaseScore
			}
			cvssVector = v.CVSSv3.Vector
		} else if v.CVSSv2 != nil && v.CVSSv2.Score > 0 {
			cvssScore = v.CVSSv2.Score
		}
		
		// If still no CVSS, try to extract from database_specific
		if cvssScore == 0 && v.DatabaseSpecific != nil {
			if dbSpec, ok := v.DatabaseSpecific.(map[string]interface{}); ok {
				// Try common CVSS fields in database_specific
				if cvssVal, ok := dbSpec["cvss_score"]; ok {
					if score, ok := cvssVal.(float64); ok {
						cvssScore = score
					}
				}
				if cvssVal, ok := dbSpec["cvss3_score"]; ok {
					if score, ok := cvssVal.(float64); ok {
						cvssScore = score
					}
				}
				if vectorVal, ok := dbSpec["cvss_vector"]; ok {
					if vec, ok := vectorVal.(string); ok {
						cvssVector = vec
					}
				}
			}
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

		// Extract CVE ID from references if ID is GHSA-*
		cveID := ""
		if !strings.HasPrefix(v.ID, "CVE-") {
			cveID = extractCVEFromReferences(v.ID, v.References)
		} else {
			cveID = v.ID
		}

		vuln := types.Vulnerability{
			ID:          v.ID,
			CVEID:       cveID,
			Summary:     v.Summary,
			Description: v.Details,
			Severity:    sev,
			CVSSScore:   cvssScore,
			CVSSVector:  cvssVector,
			References:  refs,
			PublishedAt: published,
			ModifiedAt:  modified,
			Sources:     extractSourcesFromID(v.ID),
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// BatchQuery queries multiple packages and returns vulnerabilities indexed by package@version.
func (c *Client) BatchQuery(pkgs []struct {
	name    string
	version string
}) (map[string][]types.Vulnerability, error) {
	results := make(map[string][]types.Vulnerability)

	for _, pkg := range pkgs {
		key := fmt.Sprintf("%s@%s", pkg.name, pkg.version)
		vulns, err := c.Query(pkg.name, pkg.version)
		if err != nil {
			// Continue on error, mark as empty but don't fail
			vulns = []types.Vulnerability{}
		}
		results[key] = vulns
	}

	return results, nil
}

// CalculateRiskScore computes a risk score based on severity and context.
// Returns a value 0-100.
func CalculateRiskScore(severity types.Severity, inProduction bool) int {
	return CalculateRiskScoreWithDepth(severity, inProduction, 0)
}

// CalculateRiskScoreWithDepth computes risk score with supply chain depth modifier.
// depth: 0 = direct, 1 = transitive (1 level), 2 = deeper, etc.
func CalculateRiskScoreWithDepth(severity types.Severity, inProduction bool, depth int) int {
	baseScore := map[types.Severity]int{
		types.Critical: 90,
		types.High:     70,
		types.Medium:   50,
		types.Low:      20,
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
func (c *Client) ScanGraphVulnerabilities(graph *types.DependencyGraph) error {
	for _, node := range graph.Nodes {
		eco := node.Ecosystem
		if eco == "" {
			eco = graph.Ecosystem
		}
		if eco == "" {
			eco = types.EcosystemNPM
		}

		vulns, err := c.QueryWithEcosystem(node.Name, node.Version, eco)
		if err != nil {
			// Log but continue
			continue
		}

		// Calculate risk scores with depth modifier
		for i := range vulns {
			vulns[i].RiskScore = CalculateRiskScoreWithDepth(
				vulns[i].Severity,
				node.Type == types.Production,
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
func extractSeverity(sev interface{}) types.Severity {
	if sev == nil {
		return ""
	}

	switch v := sev.(type) {
	case string:
		// Direct string value
		return types.Severity(v)
	case []interface{}:
		// Array - take first element
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return types.Severity(str)
			}
		}
	case map[string]interface{}:
		// Object - try to extract from common fields
		if cvss, ok := v["cvssv3"]; ok {
			if cvssObj, ok := cvss.(map[string]interface{}); ok {
				if severity, ok := cvssObj["severity"].(string); ok {
					return types.Severity(severity)
				}
			}
		}
		if cvss, ok := v["cvssv2"]; ok {
			if cvssObj, ok := cvss.(map[string]interface{}); ok {
				if severity, ok := cvssObj["severity"].(string); ok {
					return types.Severity(severity)
				}
			}
		}
	}

	return ""
}

// deriveSeverityFromCVSSv2 derives severity level from CVSS v2 score.
// CVSS v2 uses 0-10 scale:
// 0-3.9: Low
// 4.0-6.9: Medium
// 7.0-10.0: High/Critical
func deriveSeverityFromCVSSv2(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.Critical
	case score >= 7.0:
		return types.High
	case score >= 4.0:
		return types.Medium
	default:
		return types.Low
	}
}

var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// extractCVEFromReferences extracts CVE ID from OSV references.
// When OSV returns GHSA-* ID, CVE might be in references URLs or IDs.
// Returns CVE ID if found, empty string otherwise.
func extractCVEFromReferences(id string, references []struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}) string {
	// If ID is already a CVE, return it
	if strings.HasPrefix(id, "CVE-") {
		return id
	}

	// Look for CVE pattern in references URLs
	// CVE IDs can appear in URLs like:
	// - https://nvd.nist.gov/vuln/detail/CVE-2024-1234
	// - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234
	for _, ref := range references {
		matches := cveRegex.FindString(ref.URL)
		if matches != "" {
			return matches
		}
	}

	return ""
}

// extractSourcesFromID extracts vulnerability sources based on ID format.
// CVE IDs start with "CVE-"
// GHSA IDs start with "GHSA-" and are GitHub Security Advisories
// Returns a list of detected sources
func extractSourcesFromID(id string) []string {
	sources := []string{"osv"} // OSV is always the aggregator

	if strings.HasPrefix(id, "CVE-") {
		// CVE identifiers come from NVD/MITRE
		sources = append(sources, "nvd", "mitre")
	} else if strings.HasPrefix(id, "GHSA-") {
		// GHSA identifiers are from GitHub
		sources = append(sources, "github")
	}

	return sources
}
