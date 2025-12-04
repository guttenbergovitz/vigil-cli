package scanner

import (
	"bytes"
	"testing"
)

func TestParseNPMLockFile(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *Dependencies
		wantErr bool
	}{
		{
			name: "simple npm lock v2",
			input: []byte(`{
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.18.0",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
      "dev": false
    },
    "node_modules/jest": {
      "version": "29.0.0",
      "resolved": "https://registry.npmjs.org/jest/-/jest-29.0.0.tgz",
      "dev": true
    }
  }
}`),
			want: &Dependencies{
				Production: map[string]string{
					"express": "4.18.0",
				},
				Development: map[string]string{
					"jest": "29.0.0",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty packages",
			input:   []byte(`{"lockfileVersion": 2, "packages": {}}`),
			want:    &Dependencies{Production: make(map[string]string), Development: make(map[string]string)},
			wantErr: false,
		},
		{
			name:    "invalid json",
			input:   []byte(`{invalid}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNPMLock(bytes.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseNPMLock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got.Production) != len(tt.want.Production) {
				t.Errorf("production deps count: got %d, want %d", len(got.Production), len(tt.want.Production))
			}
			for pkg, ver := range tt.want.Production {
				if got.Production[pkg] != ver {
					t.Errorf("production dep %s: got %s, want %s", pkg, got.Production[pkg], ver)
				}
			}
			if len(got.Development) != len(tt.want.Development) {
				t.Errorf("dev deps count: got %d, want %d", len(got.Development), len(tt.want.Development))
			}
			for pkg, ver := range tt.want.Development {
				if got.Development[pkg] != ver {
					t.Errorf("dev dep %s: got %s, want %s", pkg, got.Development[pkg], ver)
				}
			}
		})
	}
}

func TestFindLockFile(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		want    string
		wantErr bool
	}{
		{
			name:    "npm lock found",
			files:   []string{"package-lock.json"},
			want:    "package-lock.json",
			wantErr: false,
		},
		{
			name:    "yarn lock found",
			files:   []string{"yarn.lock"},
			want:    "yarn.lock",
			wantErr: false,
		},
		{
			name:    "pnpm lock found",
			files:   []string{"pnpm-lock.yaml"},
			want:    "pnpm-lock.yaml",
			wantErr: false,
		},
		{
			name:    "no lock file",
			files:   []string{"package.json"},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test will use temporary files in real implementation
			// For now, it documents expected behavior
			_ = tt
		})
	}
}
