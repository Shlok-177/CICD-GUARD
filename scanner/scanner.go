package scanner

import (
	"fmt"
	"os"

	"cicd-guard/rules"
	"cicd-guard/types"
)

// Scanner scans CI/CD pipeline files for security issues
type Scanner struct {
	rules *rules.Engine
	ig    *IgnoreManager
}

// NewScanner creates a new scanner instance
func NewScanner() *Scanner {
	return &Scanner{
		rules: rules.NewEngine(),
		ig:    LoadIgnore("."),
	}
}

// LoadCustomRules loads custom rules from a YAML file
func (s *Scanner) LoadCustomRules(rulesFile string) error {
	return s.rules.LoadCustomRules(rulesFile)
}

// Scan scans the specified paths for CI/CD pipeline files
func (s *Scanner) Scan(paths ...string) (*Findings, error) {
	findings := NewFindings()

	var allFiles []string
	for _, p := range paths {
		// If the path is a directory, discover pipeline files within it
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("failed to get file info for %s: %w", p, err)
		}
		if info.IsDir() {
			detected, err := DetectPipelineFiles(p)
			if err != nil {
				return nil, fmt.Errorf("failed to detect pipeline files in %s: %w", p, err)
			}
			allFiles = append(allFiles, detected...)
		} else {
			// If it's a file, just add it
			allFiles = append(allFiles, p)
		}
	}

	// Scan each file
	for _, file := range allFiles {
		if s.ig != nil && s.ig.ShouldIgnoreFile(file) {
			continue
		}
		fileFindings, err := s.scanFile(file)
		if err != nil {
			// Log error and continue scanning other files
			fmt.Printf("failed to scan %s: %v\n", file, err)
			continue
		}
		for _, f := range fileFindings {
			if s.ig != nil && s.ig.ShouldIgnoreLine(f.Context) {
				continue
			}
			findings.Add(f)
		}
	}

	return findings, nil
}

// scanFile scans a single CI/CD file for issues
func (s *Scanner) scanFile(filePath string) ([]types.Finding, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Run all rules against the file content
	return s.rules.RunRules(filePath, string(content)), nil
}
