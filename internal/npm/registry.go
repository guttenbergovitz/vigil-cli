package npm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client queries npm registry for package metadata.
type Client struct {
	endpoint   string
	timeout    int
	httpClient *http.Client
}

// New creates npm registry client.
func New(endpoint string, timeout int) *Client {
	return &Client{
		endpoint:   endpoint,
		timeout:    timeout,
		httpClient: &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}
}

// PackageMetadata represents npm registry response.
type PackageMetadata struct {
	Time map[string]string `json:"time"` // version -> ISO8601 timestamp
}

// GetReleaseDate fetches package release date from npm registry.
func (c *Client) GetReleaseDate(name, version string) (*time.Time, error) {
	url := fmt.Sprintf("%s/%s/%s", c.endpoint, name, version)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("npm registry request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Package/version not found - not an error, just no date available
		return nil, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("npm registry error: HTTP %d", resp.StatusCode)
	}

	var metadata PackageMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("parse npm response: %w", err)
	}

	// Get release timestamp for this version
	timestamp, exists := metadata.Time[version]
	if !exists {
		return nil, nil
	}

	// Parse ISO8601 timestamp
	released, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse release date: %w", err)
	}

	return &released, nil
}
