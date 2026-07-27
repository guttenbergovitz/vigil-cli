package types

import (
	"testing"
	"time"
)

func TestFilterTemporalFalsePositives(t *testing.T) {
	// Test date: 2020-02-20
	pkgReleased := time.Date(2020, 2, 20, 0, 0, 0, 0, time.UTC)

	// CVE dates
	before := time.Date(2019, 1, 15, 0, 0, 0, 0, time.UTC)
	same := time.Date(2020, 2, 20, 0, 0, 0, 0, time.UTC)
	after := time.Date(2021, 2, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		packageReleased *time.Time
		vulns           []Vulnerability
		expectedCount   int
		description     string
	}{
		{
			name:            "nil_release_date",
			packageReleased: nil,
			vulns: []Vulnerability{
				{ID: "CVE-2019-1", PublishedAt: &before},
				{ID: "CVE-2021-1", PublishedAt: &after},
			},
			expectedCount: 2,
			description:   "No release date - include all",
		},
		{
			name:            "filter_before_release",
			packageReleased: &pkgReleased,
			vulns: []Vulnerability{
				{ID: "CVE-2019-1", PublishedAt: &before},
			},
			expectedCount: 0,
			description:   "CVE published before release - filter out",
		},
		{
			name:            "keep_on_release_day",
			packageReleased: &pkgReleased,
			vulns: []Vulnerability{
				{ID: "CVE-2020-1", PublishedAt: &same},
			},
			expectedCount: 1,
			description:   "CVE published on release day - keep",
		},
		{
			name:            "keep_after_release",
			packageReleased: &pkgReleased,
			vulns: []Vulnerability{
				{ID: "CVE-2021-1", PublishedAt: &after},
			},
			expectedCount: 1,
			description:   "CVE published after release - keep",
		},
		{
			name:            "keep_nil_published_date",
			packageReleased: &pkgReleased,
			vulns: []Vulnerability{
				{ID: "CVE-UNKNOWN", PublishedAt: nil},
			},
			expectedCount: 1,
			description:   "No CVE publish date - conservative, keep",
		},
		{
			name:            "mixed_vulns",
			packageReleased: &pkgReleased,
			vulns: []Vulnerability{
				{ID: "CVE-2019-1", PublishedAt: &before},  // Filter
				{ID: "CVE-2020-1", PublishedAt: &same},    // Keep
				{ID: "CVE-2021-1", PublishedAt: &after},   // Keep
				{ID: "CVE-UNKNOWN", PublishedAt: nil},     // Keep
			},
			expectedCount: 3,
			description:   "Mix of dates - filter only before release",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterTemporalFalsePositives(tt.packageReleased, tt.vulns)

			if len(result) != tt.expectedCount {
				t.Errorf("%s: expected %d vulns, got %d", tt.description, tt.expectedCount, len(result))
			}
		})
	}
}

func TestShouldIncludeVuln(t *testing.T) {
	pkgReleased := time.Date(2020, 2, 20, 0, 0, 0, 0, time.UTC)
	before := time.Date(2019, 1, 15, 0, 0, 0, 0, time.UTC)
	after := time.Date(2021, 2, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		vuln     Vulnerability
		expected bool
	}{
		{
			name:     "nil_publish_date",
			vuln:     Vulnerability{ID: "CVE-1", PublishedAt: nil},
			expected: true,
		},
		{
			name:     "published_before",
			vuln:     Vulnerability{ID: "CVE-2", PublishedAt: &before},
			expected: false,
		},
		{
			name:     "published_after",
			vuln:     Vulnerability{ID: "CVE-3", PublishedAt: &after},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldIncludeVuln(&pkgReleased, tt.vuln)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestFilterWithStats(t *testing.T) {
	pkgReleased := time.Date(2020, 2, 20, 0, 0, 0, 0, time.UTC)
	before := time.Date(2019, 1, 15, 0, 0, 0, 0, time.UTC)
	after := time.Date(2021, 2, 15, 0, 0, 0, 0, time.UTC)

	vulns := []Vulnerability{
		{ID: "CVE-2019-1", PublishedAt: &before},
		{ID: "CVE-2019-2", PublishedAt: &before},
		{ID: "CVE-2021-1", PublishedAt: &after},
		{ID: "CVE-2021-2", PublishedAt: &after},
		{ID: "CVE-2021-3", PublishedAt: &after},
	}

	filtered, stats := FilterWithStats(&pkgReleased, vulns)

	if stats.TotalVulns != 5 {
		t.Errorf("expected 5 total vulns, got %d", stats.TotalVulns)
	}
	if stats.FilteredVulns != 2 {
		t.Errorf("expected 2 filtered vulns, got %d", stats.FilteredVulns)
	}
	if stats.KeptVulns != 3 {
		t.Errorf("expected 3 kept vulns, got %d", stats.KeptVulns)
	}
	if len(filtered) != 3 {
		t.Errorf("expected 3 vulns in result, got %d", len(filtered))
	}
}
