package osv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

func TestQueryPackage(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		version   string
		response  string
		wantVulns int
		wantErr   bool
	}{
		{
			name:    "vulnerable package",
			pkg:     "express",
			version: "4.18.0",
			response: `{
  "vulns": [
    {
      "id": "CVE-2024-1234",
      "summary": "XSS vulnerability",
      "severity": "medium",
      "published": "2024-01-15T00:00:00Z",
      "modified": "2024-01-20T00:00:00Z",
      "references": [
        {
          "type": "WEB",
          "url": "https://example.com/advisory"
        }
      ]
    }
  ]
}`,
			wantVulns: 1,
			wantErr:   false,
		},
		{
			name:      "no vulnerabilities",
			pkg:       "lodash",
			version:   "4.17.21",
			response:  `{"vulns": []}`,
			wantVulns: 0,
			wantErr:   false,
		},
		{
			name:      "valid response no vulns",
			pkg:       "safe-pkg",
			version:   "1.0.0",
			response:  `{"vulns": null}`,
			wantVulns: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tt.response)
			}))
			defer server.Close()

			client := New(server.URL, 10)
			vulns, err := client.Query(tt.pkg, tt.version)

			if (err != nil) != tt.wantErr {
				t.Errorf("Query() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(vulns) != tt.wantVulns {
				t.Errorf("vulnerability count: got %d, want %d", len(vulns), tt.wantVulns)
			}
		})
	}
}

func TestBatchQuery(t *testing.T) {
	pkgs := []struct {
		name    string
		version string
	}{
		{"express", "4.18.0"},
		{"lodash", "4.17.21"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"vulns": []}`)
	}))
	defer server.Close()

	client := New(server.URL, 10)
	results, err := client.BatchQuery(pkgs)
	if err != nil {
		t.Errorf("BatchQuery() error = %v", err)
		return
	}
	if len(results) != len(pkgs) {
		t.Errorf("results count: got %d, want %d", len(results), len(pkgs))
	}
}

func TestRiskScore(t *testing.T) {
	tests := []struct {
		name     string
		severity models.Severity
		inProd   bool
		wantMin  int
		wantMax  int
	}{
		{"critical in prod", models.Critical, true, 80, 100},
		{"high in prod", models.High, true, 60, 80},
		{"medium in prod", models.Medium, true, 40, 60},
		{"low in dev", models.Low, false, 0, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateRiskScore(tt.severity, tt.inProd)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("risk score %d not in range [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}
