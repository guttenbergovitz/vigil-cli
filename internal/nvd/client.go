package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// Client provides access to NVD API for CVE data
type Client struct {
	endpoint   string
	timeout    int
	apiKey     string
	httpClient *http.Client
}

// New creates a new NVD client
func New(endpoint, apiKey string, timeout int) *Client {
	return &Client{
		endpoint:   endpoint,
		timeout:    timeout,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}
}

// QueryResponse represents NVD API v2.0 response for CVE search
type QueryResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Value string `json:"value"`
				Lang  string `json:"lang"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						Version      string  `json:"version"`
						VectorString string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						Version      string  `json:"version"`
						VectorString string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						Version   string  `json:"version"`
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
	TotalResults int `json:"totalResults"`
}

// QueryCPE queries NVD for vulnerabilities by CPE
// CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
// Note: This requires NVD API key and may be rate-limited
func (c *Client) QueryCPE(vendor, product, version string) ([]models.Vulnerability, error) {
	// Build CPE URI
	cpeURI := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)

	// Build URL with API key if available
	url := fmt.Sprintf("%s?cpeName=%s", c.endpoint, cpeURI)
	if c.apiKey != "" {
		url += fmt.Sprintf("&apiKey=%s", c.apiKey)
	}

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("NVD query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error: %d %s", resp.StatusCode, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}

	var vulns []models.Vulnerability
	for _, vuln := range queryResp.Vulnerabilities {
		summary := ""
		if len(vuln.CVE.Descriptions) > 0 {
			summary = vuln.CVE.Descriptions[0].Value
		}

		// Extract CVSS score from metrics
		cvssScore := 0.0
		severity := models.Low
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			cvssData := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData
			cvssScore = cvssData.BaseScore
			severity = parseSeverity(cvssData.BaseSeverity)
		} else if len(vuln.CVE.Metrics.CVSSMetricV30) > 0 {
			cvssData := vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData
			cvssScore = cvssData.BaseScore
			severity = parseSeverity(cvssData.BaseSeverity)
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			cvssData := vuln.CVE.Metrics.CVSSMetricV2[0].CVSSData
			cvssScore = cvssData.BaseScore
			// Map CVSS v2 score to severity
			if cvssScore >= 9.0 {
				severity = models.Critical
			} else if cvssScore >= 7.0 {
				severity = models.High
			} else if cvssScore >= 4.0 {
				severity = models.Medium
			}
		}

		var published *time.Time
		if vuln.CVE.Published != "" {
			if t, err := time.Parse(time.RFC3339, vuln.CVE.Published); err == nil {
				published = &t
			}
		}

		vulns = append(vulns, models.Vulnerability{
			ID:          vuln.CVE.ID,
			Summary:     summary,
			Severity:    severity,
			CVSSScore:   cvssScore,
			PublishedAt: published,
			Sources:     []string{"nvd"},
		})
	}

	return vulns, nil
}

// QueryCVE queries NVD API for a specific CVE ID
// Returns CVE data including title, description, and severity from MITRE/NVD
func (c *Client) QueryCVE(cveID string) (*models.Vulnerability, error) {
	// Build URL with API key if available
	url := fmt.Sprintf("%s?cveId=%s", c.endpoint, cveID)
	if c.apiKey != "" {
		url += fmt.Sprintf("&apiKey=%s", c.apiKey)
	}

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("NVD query CVE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error: %d %s", resp.StatusCode, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}

	if len(queryResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}

	vuln := queryResp.Vulnerabilities[0]

	// Extract title and description (prefer English)
	var title, description string
	for _, desc := range vuln.CVE.Descriptions {
		if desc.Lang == "en" || (title == "" && desc.Lang == "") {
			if title == "" {
				// Extract first sentence or first 80 chars as short title
				fullText := desc.Value
				description = fullText
				
				// Try to find first sentence (ends with . ! or ?)
				sentenceEnd := -1
				for i, r := range fullText {
					if r == '.' || r == '!' || r == '?' {
						if i+1 < len(fullText) && fullText[i+1] == ' ' {
							sentenceEnd = i + 1
							break
						}
					}
				}
				
				if sentenceEnd > 0 && sentenceEnd <= 120 {
					title = fullText[:sentenceEnd]
				} else {
					// Use first 80 chars if no sentence end found
					if len(fullText) > 80 {
						title = fullText[:77] + "..."
					} else {
						title = fullText
					}
				}
			} else {
				description = desc.Value
			}
		}
	}
	if title == "" && len(vuln.CVE.Descriptions) > 0 {
		fullText := vuln.CVE.Descriptions[0].Value
		description = fullText
		
		// Extract first sentence
		sentenceEnd := -1
		for i, r := range fullText {
			if r == '.' || r == '!' || r == '?' {
				if i+1 < len(fullText) && fullText[i+1] == ' ' {
					sentenceEnd = i + 1
					break
				}
			}
		}
		
		if sentenceEnd > 0 && sentenceEnd <= 120 {
			title = fullText[:sentenceEnd]
		} else {
			if len(fullText) > 80 {
				title = fullText[:77] + "..."
			} else {
				title = fullText
			}
		}
	}

	// Extract CVSS score from metrics (prefer V3.1, then V3.0, then V2)
	cvssScore := 0.0
	var cvssVector string
	severity := models.Low
	
	// Try CVSS v3.1 first
	if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
		cvssData := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData
		cvssScore = cvssData.BaseScore
		cvssVector = cvssData.VectorString
		severity = parseSeverity(cvssData.BaseSeverity)
	} else if len(vuln.CVE.Metrics.CVSSMetricV30) > 0 {
		// Try CVSS v3.0
		cvssData := vuln.CVE.Metrics.CVSSMetricV30[0].CVSSData
		cvssScore = cvssData.BaseScore
		cvssVector = cvssData.VectorString
		severity = parseSeverity(cvssData.BaseSeverity)
	} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
		// Fallback to CVSS v2
		cvssData := vuln.CVE.Metrics.CVSSMetricV2[0].CVSSData
		cvssScore = cvssData.BaseScore
		// Map CVSS v2 score to severity
		if cvssScore >= 9.0 {
			severity = models.Critical
		} else if cvssScore >= 7.0 {
			severity = models.High
		} else if cvssScore >= 4.0 {
			severity = models.Medium
		}
	}

	var published *time.Time
	if vuln.CVE.Published != "" {
		if t, err := time.Parse(time.RFC3339, vuln.CVE.Published); err == nil {
			published = &t
		}
	}

	return &models.Vulnerability{
		ID:            vuln.CVE.ID,
		CVEID:         vuln.CVE.ID,
		Summary:       title,
		Description:   description,
		CVETitle:      title,
		CVEDescription: description,
		Severity:      severity,
		CVESeverity:   severity,
		CVSSScore:     cvssScore,
		CVSSVector:    cvssVector,
		PublishedAt:   published,
		Sources:       []string{"nvd", "mitre"},
	}, nil
}

// parseSeverity converts CVSS severity string to models.Severity
func parseSeverity(s string) models.Severity {
	severityUpper := strings.ToUpper(strings.TrimSpace(s))
	switch severityUpper {
	case "CRITICAL":
		return models.Critical
	case "HIGH":
		return models.High
	case "MEDIUM":
		return models.Medium
	case "LOW":
		return models.Low
	default:
		// Try to match partial strings
		if strings.Contains(severityUpper, "CRITICAL") {
			return models.Critical
		}
		if strings.Contains(severityUpper, "HIGH") {
			return models.High
		}
		if strings.Contains(severityUpper, "MEDIUM") {
			return models.Medium
		}
		if strings.Contains(severityUpper, "LOW") {
			return models.Low
		}
		return models.Medium // Default to medium instead of low for unknown
	}
}
