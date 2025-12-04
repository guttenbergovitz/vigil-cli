package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// QueryGHSA queries GitHub Security Advisory API for a specific GHSA ID
// Returns CVSS score and other details
func (c *Client) QueryGHSA(ghsaID string) (*types.Vulnerability, error) {
	if c.token == "" {
		// Try without auth first
		return c.queryGHSAWithoutAuth(ghsaID)
	}

	url := fmt.Sprintf("%s/graphql", c.endpoint)
	
	// GraphQL query for GitHub Security Advisory
	query := fmt.Sprintf(`{
		"query": "query { securityAdvisory(ghsaId: \"%s\") { ghsaId summary description severity cvss { score vectorString } publishedAt updatedAt identifiers { type value } } }"
	}`, ghsaID)

	req, err := http.NewRequest("POST", url, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub GraphQL query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try without auth
		return c.queryGHSAWithoutAuth(ghsaID)
	}

	var graphqlResp struct {
		Data struct {
			SecurityAdvisory struct {
				GHSAID       string `json:"ghsaId"`
				Summary      string `json:"summary"`
				Description  string `json:"description"`
				Severity     string `json:"severity"`
				CVSS         struct {
					Score      float64 `json:"score"`
					VectorString string `json:"vectorString"`
				} `json:"cvss"`
				PublishedAt string `json:"publishedAt"`
				UpdatedAt   string `json:"updatedAt"`
				Identifiers []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"identifiers"`
			} `json:"securityAdvisory"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		return nil, fmt.Errorf("decode GraphQL response: %w", err)
	}

	if len(graphqlResp.Errors) > 0 {
		return c.queryGHSAWithoutAuth(ghsaID)
	}

	adv := graphqlResp.Data.SecurityAdvisory
	if adv.GHSAID == "" {
		return nil, fmt.Errorf("GHSA %s not found", ghsaID)
	}

	var published *time.Time
	if adv.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, adv.PublishedAt); err == nil {
			published = &t
		}
	}

	cveID := ""
	for _, id := range adv.Identifiers {
		if id.Type == "CVE" {
			cveID = id.Value
			break
		}
	}

	severity := types.Severity(strings.ToLower(adv.Severity))
	if severity == "" {
		severity = types.Medium
	}

	return &types.Vulnerability{
		ID:          adv.GHSAID,
		CVEID:       cveID,
		Summary:     adv.Summary,
		Description: adv.Description,
		Severity:    severity,
		CVSSScore:   adv.CVSS.Score,
		CVSSVector:  adv.CVSS.VectorString,
		PublishedAt: published,
		Sources:     []string{"github"},
	}, nil
}

// queryGHSAWithoutAuth tries to fetch GHSA from public API endpoint
func (c *Client) queryGHSAWithoutAuth(ghsaID string) (*types.Vulnerability, error) {
	// GitHub Security Advisories are public, try REST API
	url := fmt.Sprintf("https://api.github.com/advisories/%s", ghsaID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub advisory query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d %s", resp.StatusCode, string(body))
	}

	var advisory struct {
		GHSAID      string `json:"ghsa_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		CVSS        struct {
			Score       float64 `json:"score"`
			VectorString string `json:"vector_string"`
		} `json:"cvss"`
		PublishedAt string `json:"published_at"`
		UpdatedAt   string `json:"updated_at"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&advisory); err != nil {
		return nil, fmt.Errorf("decode GitHub response: %w", err)
	}

	if advisory.GHSAID == "" {
		return nil, fmt.Errorf("GHSA %s not found", ghsaID)
	}

	var published *time.Time
	if advisory.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, advisory.PublishedAt); err == nil {
			published = &t
		}
	}

	cveID := ""
	for _, id := range advisory.Identifiers {
		if id.Type == "CVE" {
			cveID = id.Value
			break
		}
	}

	severity := types.Severity(strings.ToLower(advisory.Severity))
	if severity == "" {
		severity = types.Medium
	}

	return &types.Vulnerability{
		ID:          advisory.GHSAID,
		CVEID:       cveID,
		Summary:     advisory.Summary,
		Description: advisory.Description,
		Severity:    severity,
		CVSSScore:   advisory.CVSS.Score,
		CVSSVector:  advisory.CVSS.VectorString,
		PublishedAt: published,
		Sources:     []string{"github"},
	}, nil
}

