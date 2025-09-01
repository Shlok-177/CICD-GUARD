package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cicd-guard/scanner" // Assuming scanner is in the same module
)

// Helper function to create temporary pipeline files for testing
func createTestPipelineFiles(t *testing.T, tmpDir string) []string {
	files := []string{
		"testdata/github/workflows/build.yml",
		"testdata/azure-ci/deploy.yaml",
		"testdata/gitlab/.gitlab-ci.yml",
		"testdata/custom/ci-pipeline.yaml",
		"testdata/not-a-pipeline.txt", // Should be ignored
	}

	createdPaths := []string{}
	for _, file := range files {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("test content"), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", fullPath, err)
		}
		if strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml") || strings.Contains(file, "Jenkinsfile") || strings.Contains(file, "pipeline") {
			createdPaths = append(createdPaths, fullPath)
		}
	}
	return createdPaths
}

// Helper to capture stdout
func captureOutput(f func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// Helper to simulate stdin
func simulateInput(input string) *os.File {
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(input)
	w.Close()
	return r
}

// ResetFlags resets the flags for the scanCmd
func ResetScanCommandFlags() {
	allFiles = false
	secretsOnly = false
	excludeFiles = []string{}
	// Reset cobra flags explicitly
	scanCmd.ResetFlags() // Reset scanCmd specific flags
	rootCmd.ResetFlags() // Reset rootCmd and its persistent flags

	// Re-initialize persistent flags for rootCmd
	rootCmd.PersistentFlags().StringVarP(&path, "path", "p", ".", "Path to scan (default: current directory)")
	rootCmd.PersistentFlags().BoolVarP(&json, "json", "j", false, "Output results in JSON format")
	rootCmd.PersistentFlags().StringVarP(&severity, "severity", "s", "", "Filter results by severity (HIGH, MEDIUM, LOW)")
	rootCmd.PersistentFlags().StringVarP(&rules, "rules", "r", "", "Path to custom rules YAML file")

	// Re-add scanCmd specific flags
	scanCmd.Flags().BoolVar(&allFiles, "all", false, "Scan all detected pipeline files automatically")
	scanCmd.Flags().BoolVar(&secretsOnly, "secrets-only", false, "Run only context-aware secret detection (skip other rules)")
	scanCmd.Flags().StringSliceVar(&excludeFiles, "exclude", []string{}, "Comma-separated list of file indices or filenames to exclude")
}

func TestScanCommandAllFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_scan_all")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	expectedFiles := createTestPipelineFiles(t, tmpDir)

	// Save original os.Args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Reset flags before each test
	ResetScanCommandFlags()

	// Set up command line arguments
	os.Args = []string{"cicd-guard", "scan", "--all", "--path", tmpDir}

	// Capture output
	output := captureOutput(func() {
		// Execute the command
		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("scan command failed: %v", err)
		}
	})

	expectedOutput := fmt.Sprintf("✅ Scanning all %d pipeline files...\n", len(expectedFiles))
	if !strings.Contains(output, expectedOutput) {
		t.Errorf("expected output to contain %q, got %q", expectedOutput, output)
	}
	// Further checks could involve mocking the scanner.Scan method to verify which files were passed
}

func TestScanCommandExcludeFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_scan_exclude")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	allDetectedFiles := createTestPipelineFiles(t, tmpDir)

	// Test exclude by index
	t.Run("Exclude by index", func(t *testing.T) {
		// Reset flags before each sub-test
		ResetScanCommandFlags()

		// Exclude the first and third file (1-based index)
		excludeIndices := []string{"1", "3"}
		expectedFilesAfterExclusion := scanner.FilterFiles(allDetectedFiles, excludeIndices)

		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()
		os.Args = []string{"cicd-guard", "scan", "--exclude", strings.Join(excludeIndices, ","), "--path", tmpDir}

		output := captureOutput(func() {
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("scan command failed: %v", err)
			}
		})

		expectedOutput := fmt.Sprintf("✅ Scanning %d selected files (excluded: %s)...\n", len(expectedFilesAfterExclusion), strings.Join(excludeIndices, ", "))
		if !strings.Contains(output, expectedOutput) {
			t.Errorf("expected output to contain %q, got %q", expectedOutput, output)
		}
	})

	// Test exclude by filename
	t.Run("Exclude by filename", func(t *testing.T) {
		// Reset flags before each sub-test
		ResetScanCommandFlags()

		// Exclude specific filenames
		excludeFilenames := []string{
			filepath.Join(tmpDir, "testdata/azure-ci/deploy.yaml"),
			filepath.Join(tmpDir, "testdata/custom/ci-pipeline.yaml"),
		}
		expectedFilesAfterExclusion := scanner.FilterFiles(allDetectedFiles, excludeFilenames)

		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()
		os.Args = []string{"cicd-guard", "scan", "--exclude", strings.Join(excludeFilenames, ","), "--path", tmpDir}

		output := captureOutput(func() {
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("scan command failed: %v", err)
			}
		})

		expectedOutput := fmt.Sprintf("✅ Scanning %d selected files (excluded: %s)...\n", len(expectedFilesAfterExclusion), strings.Join(excludeFilenames, ", "))
		if !strings.Contains(output, expectedOutput) {
			t.Errorf("expected output to contain %q, got %q", expectedOutput, output)
		}
	})
}

func TestScanCommandInteractiveMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_scan_interactive")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	allDetectedFiles := createTestPipelineFiles(t, tmpDir)

	// Save original stdin/stdout and restore after test
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	// Test interactive mode - select specific files by index
	t.Run("Interactive - select by index", func(t *testing.T) {
		// Reset flags before each sub-test
		ResetScanCommandFlags()

		os.Stdin = simulateInput("1,3\n") // Select first and third file

		// Set up command line arguments (no flags for interactive mode)
		os.Args = []string{"cicd-guard", "scan", "--path", tmpDir}

		output := captureOutput(func() {
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("scan command failed: %v", err)
			}
		})

		expectedPrompt := "Select files to scan (comma separated, 'all' for everything, 'none' to cancel): "
		if !strings.Contains(output, expectedPrompt) {
			t.Errorf("expected output to contain prompt %q, got %q", expectedPrompt, output)
		}

		expectedScanMessage := "✅ Scanning 2 selected files...\n"
		if !strings.Contains(output, expectedScanMessage) {
			t.Errorf("expected output to contain %q, got %q", expectedScanMessage, output)
		}
	})

	// Test interactive mode - select all
	t.Run("Interactive - select all", func(t *testing.T) {
		// Reset flags before each sub-test
		ResetScanCommandFlags()

		os.Stdin = simulateInput("all\n")

		os.Args = []string{"cicd-guard", "scan", "--path", tmpDir}

		output := captureOutput(func() {
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("scan command failed: %v", err)
			}
		})

		expectedScanMessage := fmt.Sprintf("✅ Scanning all %d pipeline files...\n", len(allDetectedFiles))
		if !strings.Contains(output, expectedScanMessage) {
			t.Errorf("expected output to contain %q, got %q", expectedScanMessage, output)
		}
	})

	// Test interactive mode - cancel
	t.Run("Interactive - cancel", func(t *testing.T) {
		// Reset flags before each sub-test
		ResetScanCommandFlags()

		os.Stdin = simulateInput("none\n")

		os.Args = []string{"cicd-guard", "scan", "--path", tmpDir}

		output := captureOutput(func() {
			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("scan command failed: %v", err)
			}
		})

		expectedCancelMessage := "Scan cancelled.\n"
		if !strings.Contains(output, expectedCancelMessage) {
			t.Errorf("expected output to contain %q, got %q", expectedCancelMessage, output)
		}
	})
}

func TestScanSecretsOnlyFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_scan_secrets_only")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	file := filepath.Join(tmpDir, "pipeline.yml")
	if err := os.WriteFile(file, []byte("env:\n  TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd\n"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	ResetScanCommandFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cicd-guard", "scan", "--all", "--secrets-only", "--path", tmpDir}

	output := captureOutput(func() {
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("scan command failed: %v", err)
		}
	})

	if !strings.Contains(output, "🚨") && !strings.Contains(strings.ToLower(output), "secret") {
		t.Errorf("expected secret findings in output, got: %s", output)
	}
}
