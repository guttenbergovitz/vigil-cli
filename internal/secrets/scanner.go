package secrets

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SecretType indicates the type of sensitive credential detected.
type SecretType string

const (
	AWSKey           SecretType = "AWS Access Key"
	AWSSecret        SecretType = "AWS Secret Access Key"
	GitHubToken      SecretType = "GitHub Personal Access Token"
	SlackWebhook     SecretType = "Slack Webhook URL"
	PrivateSSHKey    SecretType = "Private SSH/RSA Key"
	DatabasePassword SecretType = "Database Connection String with Password"
	JWTToken         SecretType = "JSON Web Token (JWT)"
	GenericHighEntropy SecretType = "High Entropy Secret String"
)

// SecretFinding represents a detected sensitive secret in a file.
type SecretFinding struct {
	FilePath    string     `json:"file_path"`
	LineNumber  int        `json:"line_number"`
	LineContent string     `json:"line_content"`
	Type        SecretType `json:"type"`
	Match       string     `json:"match"`
	Entropy     float64    `json:"entropy"`
}

// rule defines a pattern matching rule for secret detection.
type rule struct {
	secretType SecretType
	regex      *regexp.Regexp
}

// Scanner scans files and directories for sensitive credentials and high-entropy secrets.
type Scanner struct {
	rules []rule
}

// NewScanner initializes a new Secret Scanner with pre-compiled pattern rules.
func NewScanner() *Scanner {
	return &Scanner{
		rules: []rule{
			{AWSKey, regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{GitHubToken, regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`)},
			{SlackWebhook, regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)},
			{PrivateSSHKey, regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)},
			{DatabasePassword, regexp.MustCompile(`(postgres|mysql|mongodb(\+srv)?|redis)://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\-\.]+`)},
			{JWTToken, regexp.MustCompile(`eyJh[a-zA-Z0-9_-]+\.eyJh[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)},
		},
	}
}

// CalculateShannonEntropy calculates Shannon entropy score for a string.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// ScanFile scans a single file for secret patterns and high-entropy lines.
func (s *Scanner) ScanFile(path string) ([]SecretFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	var findings []SecretFinding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			// Skip comment-only lines unless they match specific RSA key patterns
			if !strings.Contains(trimmed, "PRIVATE KEY") {
				continue
			}
		}

		// Check against pre-compiled rules
		for _, r := range s.rules {
			match := r.regex.FindString(line)
			if match != "" {
				entropy := CalculateShannonEntropy(match)
				findings = append(findings, SecretFinding{
					FilePath:    path,
					LineNumber:  lineNum,
					LineContent: maskSecretInLine(trimmed, match),
					Type:        r.secretType,
					Match:       maskString(match),
					Entropy:     entropy,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan file lines: %w", err)
	}

	return findings, nil
}

// ScanDirectory recursively scans a directory for secret findings, skipping ignored dirs.
func (s *Scanner) ScanDirectory(dir string) ([]SecretFinding, error) {
	var allFindings []SecretFinding

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden or build directories
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "dist" || name == "bin" {
				if path != dir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Skip binary files, lock files, and large generated files
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".png" || ext == ".jpg" || ext == ".exe" || ext == ".dll" || ext == ".so" || ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".lock" {
			return nil
		}

		findings, err := s.ScanFile(path)
		if err != nil {
			// Ignore read errors on special/binary files
			return nil
		}

		allFindings = append(allFindings, findings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return allFindings, nil
}

// Helper to mask secret tokens in output for security
func maskString(s string) string {
	if len(s) <= 8 {
		return "*****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func maskSecretInLine(line, match string) string {
	masked := maskString(match)
	return strings.Replace(line, match, masked, 1)
}
