package scanner

import (
	"testing"

	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

func TestBuildDependencyTree(t *testing.T) {
	tests := []struct {
		name    string
		deps    *Dependencies
		want    []models.Dependency
		wantErr bool
	}{
		{
			name: "single production dependency",
			deps: &Dependencies{
				Production: map[string]string{
					"express": "4.18.0",
				},
				Development: make(map[string]string),
			},
			want: []models.Dependency{
				{
					Name:    "express",
					Version: "4.18.0",
					Type:    models.Production,
				},
			},
			wantErr: false,
		},
		{
			name: "mixed production and dev dependencies",
			deps: &Dependencies{
				Production: map[string]string{
					"express": "4.18.0",
					"lodash":  "4.17.21",
				},
				Development: map[string]string{
					"jest":      "29.0.0",
					"typescript": "5.0.0",
				},
			},
			want: []models.Dependency{
				{Name: "express", Version: "4.18.0", Type: models.Production},
				{Name: "lodash", Version: "4.17.21", Type: models.Production},
				{Name: "jest", Version: "29.0.0", Type: models.Development},
				{Name: "typescript", Version: "5.0.0", Type: models.Development},
			},
			wantErr: false,
		},
		{
			name: "empty dependencies",
			deps: &Dependencies{
				Production:  make(map[string]string),
				Development: make(map[string]string),
			},
			want:    []models.Dependency{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildDependencyTree(tt.deps)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildDependencyTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("dependency count: got %d, want %d", len(got), len(tt.want))
				return
			}
			// Note: order may vary due to map iteration, so we check existence
			for _, wantDep := range tt.want {
				found := false
				for _, gotDep := range got {
					if gotDep.Name == wantDep.Name && gotDep.Version == wantDep.Version && gotDep.Type == wantDep.Type {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing dependency: %s@%s (%s)", wantDep.Name, wantDep.Version, wantDep.Type)
				}
			}
		})
	}
}
