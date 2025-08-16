package cmd

import (
	"github.com/spf13/cobra"
)

var (
	// Used for flags
	cfgFile  string
	path     string
	json     bool
	severity string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cicd-guard",
	Short: "A CLI tool to scan CI/CD pipeline files for security issues",
	Long: `cicd-guard is a comprehensive tool that scans CI/CD pipeline configuration files
for security vulnerabilities, hardcoded secrets, and best practice violations.

Supported file types:
- GitHub Actions (.github/workflows/*.yml)
- GitLab CI (gitlab-ci.yml)
- Jenkins (Jenkinsfile)
- Azure Pipelines (azure-pipelines.yml)

Example usage:
  cicd-guard scan --path .github/workflows
  cicd-guard scan --path . --severity HIGH --json`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&path, "path", "p", ".", "Path to scan (default: current directory)")
	rootCmd.PersistentFlags().BoolVarP(&json, "json", "j", false, "Output results in JSON format")
	rootCmd.PersistentFlags().StringVarP(&severity, "severity", "s", "", "Filter results by severity (HIGH, MEDIUM, LOW)")
}
