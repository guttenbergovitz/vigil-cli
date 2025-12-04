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

func TestParsePnpmLockFile(t *testing.T) {
	input := []byte(`
packages:
  express@4.18.0:
    dev: false
  jest@29.0.0:
    dev: true
  lodash@4.17.21:
    dev: false
`)

	got, err := ParsePnpmLock(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParsePnpmLock() error = %v", err)
	}

	// Check production deps
	if len(got.Production) != 2 {
		t.Errorf("production deps count: got %d, want 2", len(got.Production))
	}
	if got.Production["express"] != "4.18.0" {
		t.Errorf("express version: got %s, want 4.18.0", got.Production["express"])
	}
	if got.Production["lodash"] != "4.17.21" {
		t.Errorf("lodash version: got %s, want 4.17.21", got.Production["lodash"])
	}

	// Check dev deps
	if len(got.Development) != 1 {
		t.Errorf("dev deps count: got %d, want 1", len(got.Development))
	}
	if got.Development["jest"] != "29.0.0" {
		t.Errorf("jest version: got %s, want 29.0.0", got.Development["jest"])
	}
}

func TestParseLockFile(t *testing.T) {
	tests := []struct {
		name    string
		typ     LockFileType
		input   []byte
		wantPkg string
		wantVer string
	}{
		{
			name: "npm lock dispatch",
			typ:  NPMLock,
			input: []byte(`{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/express": {
      "version": "4.18.0",
      "dev": false
    }
  }
}`),
			wantPkg: "express",
			wantVer: "4.18.0",
		},
		{
			name: "pnpm lock dispatch",
			typ:  PnpmLock,
			input: []byte(`
packages:
  express@4.18.0:
    dev: false
`),
			wantPkg: "express",
			wantVer: "4.18.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLockFile(bytes.NewReader(tt.input), tt.typ)
			if err != nil {
				t.Fatalf("ParseLockFile() error = %v", err)
			}
			if got.Production[tt.wantPkg] != tt.wantVer {
				t.Errorf("package version: got %s, want %s", got.Production[tt.wantPkg], tt.wantVer)
			}
		})
	}
}

func TestParseYarnLock(t *testing.T) {
	t.Run("yarn_v1_format", func(t *testing.T) {
		input := []byte(`express@4.18.0:
  version: 4.18.0
  dependencies:
    body-parser: "~1.20.0"
    cookie: 0.4.2

body-parser@~1.20.0:
  version: 1.20.0
  dependencies:
    bytes: 3.1.0
`)
		deps, err := ParseYarnLock(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(deps.Production) != 2 {
			t.Errorf("expected 2 production deps, got %d", len(deps.Production))
		}

		if deps.Production["express"] != "4.18.0" {
			t.Errorf("expected express@4.18.0, got %s", deps.Production["express"])
		}

		if deps.Production["body-parser"] != "1.20.0" {
			t.Errorf("expected body-parser@1.20.0, got %s", deps.Production["body-parser"])
		}
	})

	t.Run("yarn_v2_format", func(t *testing.T) {
		input := []byte(`"express@npm:4.18.0":
  version: 4.18.0
  dependencies:
    cookie: "0.4.2"

"body-parser@npm:1.20.0":
  version: 1.20.0
`)
		deps, err := ParseYarnLock(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(deps.Production) != 2 {
			t.Errorf("expected 2 production deps, got %d", len(deps.Production))
		}

		if deps.Production["express"] != "4.18.0" {
			t.Errorf("expected express@4.18.0, got %s", deps.Production["express"])
		}

		if deps.Production["body-parser"] != "1.20.0" {
			t.Errorf("expected body-parser@1.20.0, got %s", deps.Production["body-parser"])
		}
	})
}
