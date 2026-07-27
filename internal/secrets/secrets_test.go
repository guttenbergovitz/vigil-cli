package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCalculateShannonEntropy verifies entropy calculation accuracy.
func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		minScore float64
		maxScore float64
	}{
		{"aaaaa", 0.0, 0.1},                                     // Low entropy (single char)
		{"abcdef1234567890", 3.8, 4.2},                          // Medium-high entropy
		{"8f95e87d7174a6b5c3ea96c31dd2c3ea96c", 3.5, 4.5},       // High entropy hash
		{"AKIAIOSFODNN7EXAMPLE", 3.2, 4.0},                      // AWS Key example
	}

	for _, tt := range tests {
		score := CalculateShannonEntropy(tt.input)
		if score < tt.minScore || score > tt.maxScore {
			t.Errorf("CalculateShannonEntropy(%q) = %f; want between %f and %f", tt.input, score, tt.minScore, tt.maxScore)
		}
	}
}

// TestScanFileForSecrets verifies secret findings in a sample file.
func TestScanFileForSecrets(t *testing.T) {
	tmpDir := t.TempDir()
	sampleFile := filepath.Join(tmpDir, "config.env")
	content := `
# Sample config file
AWS_KEY=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgres://user:supersecretpassword123@localhost:5432/mydb
SSH_KEY=-----BEGIN RSA PRIVATE KEY-----
`
	if err := os.WriteFile(sampleFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	scanner := NewScanner()
	findings, err := scanner.ScanFile(sampleFile)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
	}

	hasAWS := false
	hasDB := false
	hasSSH := false

	for _, f := range findings {
		if f.Type == AWSKey {
			hasAWS = true
		}
		if f.Type == DatabasePassword {
			hasDB = true
		}
		if f.Type == PrivateSSHKey {
			hasSSH = true
		}
	}

	if !hasAWS {
		t.Errorf("expected AWSKey finding")
	}
	if !hasDB {
		t.Errorf("expected DatabasePassword finding")
	}
	if !hasSSH {
		t.Errorf("expected PrivateSSHKey finding")
	}
}

// TestScanDirectory verifies directory scanning with file exclusions.
func TestScanDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	normalFile := filepath.Join(tmpDir, "app.py")
	gitDir := filepath.Join(tmpDir, ".git")

	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git dir: %v", err)
	}

	gitFile := filepath.Join(gitDir, "COMMIT_EDITMSG")
	if err := os.WriteFile(gitFile, []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE"), 0644); err != nil {
		t.Fatalf("failed to write git file: %v", err)
	}

	slackURL := "https://" + "hooks." + "slack.com/services/T00000000/B00000000/SAMPLESECRET12345678"
	if err := os.WriteFile(normalFile, []byte("SLACK_WEBHOOK="+slackURL), 0644); err != nil {
		t.Fatalf("failed to write app.py: %v", err)
	}

	scanner := NewScanner()
	findings, err := scanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding (excluding .git), got %d", len(findings))
	}
	if len(findings) > 0 && findings[0].Type != SlackWebhook {
		t.Errorf("expected SlackWebhook finding, got %s", findings[0].Type)
	}
}
