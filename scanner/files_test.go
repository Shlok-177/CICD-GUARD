package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectPipelineFiles(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	testFiles := []string{
		"ci.yml",
		"pipeline.yaml",
		"Jenkinsfile",
		"custom-pipeline.txt",
		"not-a-pipeline.txt",
	}
	for _, file := range testFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, file), []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Test scanning the directory
	files, err := DetectPipelineFiles(tmpDir)
	if err != nil {
		t.Fatalf("failed to detect pipeline files: %v", err)
	}
	if len(files) != 5 {
		t.Errorf("expected 5 pipeline files, but got %d", len(files))
	}

	// Test scanning a single file
	singleFile := filepath.Join(tmpDir, "ci.yml")
	files, err = DetectPipelineFiles(singleFile)
	if err != nil {
		t.Fatalf("failed to detect single pipeline file: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 pipeline file, but got %d", len(files))
	}
	if files[0] != singleFile {
		t.Errorf("expected %s, but got %s", singleFile, files[0])
	}
}

func TestFilterFiles(t *testing.T) {
	files := []string{
		"file1.yml",
		"file2.yaml",
		"file3.txt",
		"file4.jenkinsfile",
	}

	tests := []struct {
		name     string
		exclude  []string
		expected []string
	}{
		{
			name:     "No exclusion",
			exclude:  []string{},
			expected: files,
		},
		{
			name:     "Exclude by index single",
			exclude:  []string{"2"},
			expected: []string{"file1.yml", "file3.txt", "file4.jenkinsfile"},
		},
		{
			name:     "Exclude by index multiple",
			exclude:  []string{"1", "4"},
			expected: []string{"file2.yaml", "file3.txt"},
		},
		{
			name:     "Exclude by filename single",
			exclude:  []string{"file3.txt"},
			expected: []string{"file1.yml", "file2.yaml", "file4.jenkinsfile"},
		},
		{
			name:     "Exclude by filename multiple",
			exclude:  []string{"file1.yml", "file4.jenkinsfile"},
			expected: []string{"file2.yaml", "file3.txt"},
		},
		{
			name:     "Exclude mixed (index and filename)",
			exclude:  []string{"2", "file3.txt"},
			expected: []string{"file1.yml", "file4.jenkinsfile"},
		},
		{
			name:     "Exclude non-existent",
			exclude:  []string{"5", "nonexistent.txt"},
			expected: files,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterFiles(files, tt.exclude)
			if len(filtered) != len(tt.expected) {
				t.Errorf("expected %d files, got %d", len(tt.expected), len(filtered))
			}
			for i, f := range filtered {
				if f != tt.expected[i] {
					t.Errorf("expected %s at index %d, got %s", tt.expected[i], i, f)
				}
			}
		})
	}
}
