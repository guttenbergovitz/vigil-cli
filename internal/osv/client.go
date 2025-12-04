package osv

import "github.com/guttenbergovitz/vigil-cli/pkg/models"

// Client provides access to OSV API.
type Client struct {
	endpoint string
	timeout  int
}

// New creates a new OSV client with given endpoint and timeout.
func New(endpoint string, timeout int) *Client {
	return &Client{
		endpoint: endpoint,
		timeout:  timeout,
	}
}

// Query retrieves vulnerabilities for a package from OSV API.
// Returns nil for now - to be implemented.
func (c *Client) Query(pkg, version string) ([]models.Vulnerability, error) {
	return nil, nil
}
