package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"cicd-guard/rules"
	"cicd-guard/types"
)

// Scanner scans CI/CD pipeline files for security issues
type Scanner struct {
	rules *rules.Engine
}

// NewScanner creates a new scanner instance
func NewScanner() *Scanner {
	return &Scanner{
		rules: rules.NewEngine(),
	}
}

// LoadCustomRules loads custom rules from a YAML file
func (s *Scanner) LoadCustomRules(rulesFile string) error {
	return s.rules.LoadCustomRules(rulesFile)
}

// Scan scans the specified path for CI/CD pipeline files
func (s *Scanner) Scan(path string) (*Findings, error) {
	findings := NewFindings()

	// Walk through the directory
	err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check if file is a supported CI/CD file
		if s.isCICDFile(filePath) {
			fileFindings, err := s.scanFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to scan %s: %w", filePath, err)
			}
			findings.Add(fileFindings...)
		}

		return nil
	})

	return findings, err
}

// isCICDFile checks if the file is a supported CI/CD configuration file
func (s *Scanner) isCICDFile(path string) bool {
	fileName := strings.ToLower(filepath.Base(path))
	dir := strings.ToLower(filepath.Dir(path))

	// Normalize path separators for cross-platform compatibility
	dir = strings.ReplaceAll(dir, "\\", "/")

	// GitHub Actions workflows
	if strings.Contains(dir, ".github/workflows") && (strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml")) {
		return true
	}

	// GitLab CI
	if fileName == "gitlab-ci.yml" || fileName == "gitlab-ci.yaml" {
		return true
	}

	// Jenkins
	if fileName == "jenkinsfile" {
		return true
	}

	// Azure Pipelines
	if fileName == "azure-pipelines.yml" || fileName == "azure-pipelines.yaml" {
		return true
	}

	return false
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
