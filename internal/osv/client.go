package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		ID      string `json:"id"`
		Summary string `json:"summary"`
		Severity string `json:"severity"`
		Published string `json:"published"`
		Modified string `json:"modified"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

// Query retrieves vulnerabilities for a package from OSV API.
func (c *Client) Query(pkg, version string) ([]models.Vulnerability, error) {
	req := QueryRequest{}
	req.Package.PURL = fmt.Sprintf("pkg:npm/%s@%s", pkg, version)

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
		sev := models.Severity(v.Severity)
		if sev == "" {
			sev = models.Medium
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

		vulns = append(vulns, models.Vulnerability{
			ID:         v.ID,
			Summary:    v.Summary,
			Severity:   sev,
			References: refs,
			PublishedAt: published,
			ModifiedAt: modified,
		})
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

	return score
}
