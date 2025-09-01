package detector

import "testing"

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
