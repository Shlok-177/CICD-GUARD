package rules

import (
	"testing"
)

func TestContextAware_GenericCases(t *testing.T) {
	engine := NewEngine()

	// Real secret in env block should be HIGH
	{
		findings := engine.RunRules(".github/workflows/build.yml", "env:\n  MY_SECRET: ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd\n")
		if len(findings) == 0 {
			t.Fatalf("expected at least one finding")
		}
	}

	// Fake/test key in comment should be ignored
	{
		findings := engine.RunRules(".github/workflows/build.yml", "# API token: ghp_abcdefghijklmnopqrstuvwxyz0123456789abcd\n")
		if len(findings) != 0 {
			t.Fatalf("expected no findings for commented test token")
		}
	}
}
