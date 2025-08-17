package cmd

import (
	"fmt"
	"os"

	"cicd-guard/scanner"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan CI/CD pipeline files for security issues",
	Long: `Scan CI/CD pipeline configuration files for security vulnerabilities,
hardcoded secrets, and best practice violations.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Validate path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	// Create scanner
	s := scanner.NewScanner()

	// Load custom rules if specified
	if rules != "" {
		if err := s.LoadCustomRules(rules); err != nil {
			return fmt.Errorf("failed to load custom rules: %w", err)
		}
	}

	// Scan the specified path
	findings, err := s.Scan(path)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Filter by severity if specified
	if severity != "" {
		findings = findings.FilterBySeverity(severity)
	}

	// Output results
	if json {
		return findings.OutputJSON()
	}

	return findings.OutputConsole()
}
