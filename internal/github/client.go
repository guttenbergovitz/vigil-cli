package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// Client provides access to GitHub Security Alerts API
type Client struct {
	endpoint   string
	token      string
	timeout    int
	httpClient *http.Client
}

// New creates a new GitHub client
func New(token string, timeout int) *Client {
	return &Client{
		endpoint:   "https://api.github.com",
		token:      token,
		timeout:    timeout,
		httpClient: &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}
}

// AlertResponse represents GitHub Dependabot alert
type AlertResponse struct {
	Alerts []struct {
		Number        int    `json:"number"`
		State         string `json:"state"`
		DependentName string `json:"dependent_package_name"`
		Dependency    struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			ManifestPath string `json:"manifest_path"`
			Requirements struct {
				File   string `json:"file"`
				Requirement string `json:"requirement"`
			} `json:"requirements"`
		} `json:"dependency"`
		SecurityVulnerability struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Severity    string `json:"severity"`
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			PublishedAt string `json:"published_at"`
			UpdatedAt   string `json:"updated_at"`
			WithdrawnAt *string `json:"withdrawn_at"`
			Description string `json:"description"`
			CVSS        struct {
				Score  float64 `json:"score"`
				Vector string  `json:"vector_string"`
			} `json:"cvss"`
		} `json:"security_vulnerability"`
	} `json:"alerts"`
}

// QueryAlertsForRepo fetches Dependabot security alerts for a repository
// Requires GitHub token with 'security_events' scope
func (c *Client) QueryAlertsForRepo(owner, repo string) ([]types.Vulnerability, error) {
	if c.token == "" {
		return nil, fmt.Errorf("GitHub token required for security alerts")
	}

	url := fmt.Sprintf("%s/repos/%s/%s/security/dependabot/alerts?state=open", c.endpoint, owner, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d %s", resp.StatusCode, string(body))
	}

	var alertResp AlertResponse
	if err := json.NewDecoder(resp.Body).Decode(&alertResp); err != nil {
		return nil, fmt.Errorf("decode GitHub response: %w", err)
	}

	var vulns []types.Vulnerability
	for _, alert := range alertResp.Alerts {
		if alert.SecurityVulnerability.WithdrawnAt != nil {
			continue // Skip withdrawn vulnerabilities
		}

		cveID := ""
		for _, id := range alert.SecurityVulnerability.Identifiers {
			if id.Type == "CVE" {
				cveID = id.Value
				break
			}
		}
		if cveID == "" {
			cveID = fmt.Sprintf("GHSA-%d", alert.Number)
		}

		var published *time.Time
		if alert.SecurityVulnerability.PublishedAt != "" {
			if t, err := time.Parse(time.RFC3339, alert.SecurityVulnerability.PublishedAt); err == nil {
				published = &t
			}
		}

		refs := make([]string, len(alert.SecurityVulnerability.References))
		for i, ref := range alert.SecurityVulnerability.References {
			refs[i] = ref.URL
		}

		severity := types.Severity(alert.SecurityVulnerability.Severity)
		if severity == "" {
			severity = types.Medium
		}

		vulns = append(vulns, types.Vulnerability{
			ID:          cveID,
			Summary:     alert.SecurityVulnerability.Description,
			Description: alert.SecurityVulnerability.Description,
			Severity:    severity,
			CVSSScore:   alert.SecurityVulnerability.CVSS.Score,
			CVSSVector:  alert.SecurityVulnerability.CVSS.Vector,
			References:  refs,
			PublishedAt: published,
			Sources:     []string{"github"},
		})
	}

	return vulns, nil
}
