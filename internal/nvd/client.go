package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// QueryResponse represents NVD API response for CVE search
type QueryResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				DescriptionData []struct {
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		Impact struct {
			BaseMetricV3 struct {
				CVSSV3 struct {
					Score       float64 `json:"baseScore"`
					Vector      string  `json:"vectorString"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
			BaseMetricV2 struct {
				CVSSV2 struct {
					Score float64 `json:"baseScore"`
				} `json:"cvssV2"`
			} `json:"baseMetricV2"`
		} `json:"impact"`
		PublishedDate string `json:"publishedDate"`
	} `json:"vulnerabilities"`
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
		if len(vuln.CVE.Description.DescriptionData) > 0 {
			summary = vuln.CVE.Description.DescriptionData[0].Value
		}

		cvssScore := 0.0
		severity := models.Low
		if vuln.Impact.BaseMetricV3.CVSSV3.Score > 0 {
			cvssScore = vuln.Impact.BaseMetricV3.CVSSV3.Score
			severity = parseSeverity(vuln.Impact.BaseMetricV3.CVSSV3.BaseSeverity)
		} else if vuln.Impact.BaseMetricV2.CVSSV2.Score > 0 {
			cvssScore = vuln.Impact.BaseMetricV2.CVSSV2.Score
			// Map CVSS v2 score to severity (rough approximation)
			if cvssScore >= 9.0 {
				severity = models.Critical
			} else if cvssScore >= 7.0 {
				severity = models.High
			} else if cvssScore >= 4.0 {
				severity = models.Medium
			}
		}

		var published *time.Time
		if vuln.PublishedDate != "" {
			if t, err := time.Parse(time.RFC3339, vuln.PublishedDate); err == nil {
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

// parseSeverity converts CVSS severity string to models.Severity
func parseSeverity(s string) models.Severity {
	switch s {
	case "CRITICAL":
		return models.Critical
	case "HIGH":
		return models.High
	case "MEDIUM":
		return models.Medium
	case "LOW":
		return models.Low
	default:
		return models.Low
	}
}
