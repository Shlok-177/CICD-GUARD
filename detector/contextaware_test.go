package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluate_AWSKey_Real(t *testing.T) {
	d := NewContextAwareDetector(4.0)
	file := ".github/workflows/build.yml"
	content := "env:\n  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
	line := "  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE"
	finding := d.Evaluate(file, content, 2, line, "AKIAIOSFODNN7EXAMPLE", false)
	if finding == nil {
		t.Fatalf("expected finding, got nil")
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got %s", finding.Severity)
	}
}

func TestEvaluate_IgnoreCommentedKey(t *testing.T) {
	d := NewContextAwareDetector(4.0)
	file := ".github/workflows/build.yml"
	content := "# Fake key for docs: AKIAIOSFODNN7EXAMPLE\n"
	line := "# Fake key for docs: AKIAIOSFODNN7EXAMPLE"
	finding := d.Evaluate(file, content, 1, line, "AKIAIOSFODNN7EXAMPLE", false)
	if finding != nil {
		t.Fatalf("expected no finding for commented line, got one: %+v", finding)
	}
}

func TestEvaluate_RandomLookingButNonSecret(t *testing.T) {
	d := NewContextAwareDetector(4.0)
	file := "pipeline.yml"
	content := "name: ci\n  # Some non-secret value\n  value: abcdef123\n"
	line := "  value: abcdef123"
	finding := d.Evaluate(file, content, 3, line, "abcdef123", true)
	if finding != nil {
		t.Fatalf("expected no finding for low-entropy string, got one: %+v", finding)
	}
}

func TestIgnoreFileExcludesSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".cicd-guard-ignore"), []byte("file:secret.yml\n"), 0644); err != nil {
		t.Fatalf("failed to write ignore file: %v", err)
	}
	secFile := filepath.Join(dir, "secret.yml")
	content := "env:\n  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(secFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	// Change to the test directory so the ignore file is found
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(dir)

	findings, err := RunContextAwareSecrets([]string{secFile}, ScanOptions{EntropyThreshold: 4.0})
	if err != nil {
		t.Fatalf("run secrets failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings due to ignore, got %d", len(findings))
	}
}
