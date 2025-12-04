package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// SaveCache writes scan results to cache file (.vigil.cache).
func SaveCache(path string, result *models.ScanResult) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}

	return nil
}

// LoadCache reads scan results from cache file.
func LoadCache(path string) (*models.ScanResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cache file: %w", err)
	}
	defer file.Close()

	var result models.ScanResult
	if err := json.NewDecoder(file).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode cache: %w", err)
	}

	return &result, nil
}

// IsCacheValid checks if cache is still valid based on lock file hash.
func IsCacheValid(cachedHash, currentHash string) bool {
	return cachedHash == currentHash
}

// HashFile computes SHA256 hash of a file.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
