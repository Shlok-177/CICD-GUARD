package cmd

import (
	"bufio"
	"cicd-guard/detector"
	"cicd-guard/scanner"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	allFiles     bool
	secretsOnly  bool
	excludeFiles []string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Recursively scan a directory or a single file for security issues",
	Long: `Recursively scans a given directory or a single file for security vulnerabilities,
	including context-aware secret detection, hardcoded secrets, and best practice violations.
	By default, it scans the current directory for *.yml, *.yaml, Jenkinsfile, and files with "pipeline" in their name.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolVar(&allFiles, "all", false, "Scan all detected pipeline files automatically")
	scanCmd.Flags().BoolVar(&secretsOnly, "secrets-only", false, "Run only context-aware secret detection (skip other rules)")
	scanCmd.Flags().StringSliceVar(&excludeFiles, "exclude", []string{}, "Comma-separated list of file indices or filenames to exclude")
}

func runScan(cmd *cobra.Command, args []string) error {
	// If no path is specified, default to the current directory
	if path == "" {
		path = "."
	}

	// Discover pipeline files
	detectedFiles, err := scanner.DetectPipelineFiles(path)
	if err != nil {
		return fmt.Errorf("failed to detect pipeline files: %w", err)
	}

	var filesToScan []string

	if allFiles {
		filesToScan = detectedFiles
		fmt.Printf("✅ Scanning all %d pipeline files...\n", len(filesToScan))
	} else if len(excludeFiles) > 0 {
		filesToScan = scanner.FilterFiles(detectedFiles, excludeFiles)
		fmt.Printf("✅ Scanning %d selected files (excluded: %s)...\n", len(filesToScan), strings.Join(excludeFiles, ", "))
	} else {
		// Interactive mode
		fmt.Println("Detected pipeline files:")
		for i, file := range detectedFiles {
			fmt.Printf("%d) %s\n", i+1, file)
		}

		fmt.Print("\nSelect files to scan (comma separated, 'all' for everything, 'none' to cancel): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "all" {
			filesToScan = detectedFiles
			fmt.Printf("✅ Scanning all %d pipeline files...\n", len(filesToScan))
		} else if input == "none" {
			fmt.Println("Scan cancelled.")
			return nil
		} else {
			selectedIndices := make(map[int]bool)
			for _, s := range strings.Split(input, ",") {
				s = strings.TrimSpace(s)
				index, err := strconv.Atoi(s)
				if err == nil && index > 0 && index <= len(detectedFiles) {
					selectedIndices[index-1] = true
				}
			}

			for i, file := range detectedFiles {
				if selectedIndices[i] {
					filesToScan = append(filesToScan, file)
				}
			}
			fmt.Printf("✅ Scanning %d selected files...\n", len(filesToScan))
		}
	}

	if len(filesToScan) == 0 {
		fmt.Println("No files selected for scanning. Exiting.")
		return nil
	}

	if secretsOnly {
		findings, err := detector.RunContextAwareSecrets(filesToScan, detector.ScanOptions{EntropyThreshold: 4.0})
		if err != nil {
			return fmt.Errorf("secret scan failed: %w", err)
		}
		f := scanner.NewFindings()
		f.Add(findings...)
		if json {
			return f.OutputJSON()
		}
		return f.OutputConsole()
	}

	// Create scanner
	s := scanner.NewScanner()

	// Load custom rules if specified
	if rules != "" {
		if err := s.LoadCustomRules(rules); err != nil {
			return fmt.Errorf("failed to load custom rules: %w", err)
		}
	}

	// Scan the selected files
	findings, err := s.Scan(filesToScan...) // Modified to accept multiple files
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
