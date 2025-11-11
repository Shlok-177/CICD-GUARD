package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cicd-guard/ai"
	"cicd-guard/config"
	"cicd-guard/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const maxContentSize = 10 * 1024 // 10KB

var (
	aiScanAllFiles     bool
	aiScanExcludeFiles []string
	aiScanSeverity     string
	aiScanVerbose      bool
)

// aiScanCmd represents the ai-scan command
var aiScanCmd = &cobra.Command{
	Use:   "ai-scan",
	Short: "Analyze CI/CD pipeline files using AI reasoning",
	Long: `Analyze CI/CD pipeline files using AI reasoning to detect logical errors, 
security flaws, and bad practices.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")

		apiKey, err := config.GetAPIKey()
		if err != nil {
			color.Red("Error getting or validating Gemini API key: %v", err)
			// Exit immediately if API key is invalid or cannot be retrieved
			os.Exit(1)
		}

		// Find pipeline files
		pipelineFiles, err := scanner.DetectPipelineFiles(path)
		if err != nil {
			color.Red("Error finding pipeline files: %v", err)
			os.Exit(1)
		}

		if len(pipelineFiles) == 0 {
			color.Yellow("No pipeline files found in the specified path: %s", path)
			return
		}

		var filesToScan []string

		if aiScanAllFiles {
			filesToScan = pipelineFiles
			color.Cyan("✅ Scanning all %d pipeline files...", len(filesToScan))
		} else if len(aiScanExcludeFiles) > 0 {
			filesToScan = scanner.FilterFiles(pipelineFiles, aiScanExcludeFiles)
			color.Cyan("✅ Scanning %d selected files (excluded: %s)...", len(filesToScan), strings.Join(aiScanExcludeFiles, ", "))
		} else {
			// Interactive mode
			fmt.Println("Detected pipeline files:")
			for i, file := range pipelineFiles {
				fmt.Printf("%d) %s\n", i+1, file)
			}

			fmt.Print("\nSelect files to scan (comma separated, 'all' for everything, 'none' to cancel): ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			if input == "all" {
				filesToScan = pipelineFiles
				color.Cyan("✅ Scanning all %d pipeline files...", len(filesToScan))
			} else if input == "none" {
				color.Yellow("AI Scan cancelled.")
				return
			} else {
				selectedIndices := make(map[int]bool)
				for _, s := range strings.Split(input, ",") {
					s = strings.TrimSpace(s)
					index, err := strconv.Atoi(s)
					if err == nil && index > 0 && index <= len(pipelineFiles) {
						selectedIndices[index-1] = true
					}
				}

				for i, file := range pipelineFiles {
					if selectedIndices[i] {
						filesToScan = append(filesToScan, file)
					}
				}
				color.Cyan("✅ Scanning %d selected files...", len(filesToScan))
			}
		}

		if len(filesToScan) == 0 {
			color.Yellow("No files selected for AI scanning. Exiting.")
			return
		}

		var allIssues []ai.Issue
		var overallSummary string

		for _, file := range filesToScan { // Iterate over filesToScan
			content, err := os.ReadFile(file)
			if err != nil {
				color.Yellow("Skipping file %s: %v", file, err)
				continue
			}

			// Batch content for AI analysis
			fileContent := string(content)
			if len(fileContent) > maxContentSize {
				fileContent = fileContent[:maxContentSize] // Truncate if too large
				color.Yellow("File %s content truncated to %d bytes for AI analysis.", file, maxContentSize)
			}

			// Prepare content for AI
			aiContent := fmt.Sprintf("File: %s\n```\n%s\n```\n", filepath.Base(file), fileContent)

			color.Cyan("Analyzing file: %s", file)
			aiResponse, err := ai.AnalyzePipeline(apiKey, aiContent)
			if err != nil {
				color.Red("Error analyzing file %s with AI: %v", file, err)
				continue
			}

			if jsonOutput {
				jsonBytes, err := json.MarshalIndent(aiResponse, "", "  ")
				if err != nil {
					color.Red("Error marshalling AI response to JSON: %v", err)
					continue
				}
				fmt.Println(string(jsonBytes))
			} else {
				if aiResponse.Summary != "" {
					overallSummary = aiResponse.Summary
				}
				for _, issue := range aiResponse.Issues {
					allIssues = append(allIssues, issue)
				}
			}
		}

		if !jsonOutput {
			// Apply severity filter if specified
			if aiScanSeverity != "" {
				filteredIssues := []ai.Issue{}
				for _, issue := range allIssues {
					if strings.EqualFold(issue.Severity, aiScanSeverity) {
						filteredIssues = append(filteredIssues, issue)
					}
				}
				allIssues = filteredIssues
			}
			printFormattedOutput(overallSummary, allIssues)
		}
	},
}

func init() {
	rootCmd.AddCommand(aiScanCmd)
	aiScanCmd.Flags().Bool("json", false, "Output the raw Gemini JSON response.")
	aiScanCmd.PersistentFlags().StringVarP(&path, "path", "p", ".", "Path to scan (default: current directory)")
	aiScanCmd.Flags().BoolVar(&aiScanAllFiles, "all", false, "Scan all detected pipeline files automatically")
	aiScanCmd.Flags().StringSliceVar(&aiScanExcludeFiles, "exclude", []string{}, "Comma-separated list of file indices or filenames to exclude from AI scan")
	aiScanCmd.Flags().StringVarP(&aiScanSeverity, "severity", "s", "", "Filter AI scan results by severity (HIGH, MEDIUM, LOW)")
	aiScanCmd.Flags().BoolVarP(&aiScanVerbose, "verbose", "v", false, "Show verbose AI scan output, including suggestions")
}

func printFormattedOutput(summary string, issues []ai.Issue) {
	fmt.Println(color.CyanString("🤖 AI Scan Summary:"))
	if summary != "" {
		fmt.Println(summary)
	}

	if len(issues) == 0 {
		color.Green("No issues found. The pipeline follows best practices.")
		return
	}

	fmt.Printf("Found %d issues:\n", len(issues))
	for _, issue := range issues {
		var severityColor *color.Color
		switch strings.ToUpper(issue.Severity) {
		case "HIGH":
			severityColor = color.New(color.BgRed, color.FgWhite)
		case "MEDIUM":
			severityColor = color.New(color.BgYellow, color.FgBlack)
		case "LOW":
			severityColor = color.New(color.BgGreen, color.FgWhite)
		default:
			severityColor = color.New(color.BgWhite, color.FgBlack)
		}

		fmt.Printf("%s[%s]%s %s in %s (line %d)\n",
			severityColor.SprintFunc()(strings.ToUpper(issue.Severity)),
			issue.Type,
			color.WhiteString(":"),
			issue.Description,
			issue.File,
			issue.Line,
		)
		if aiScanVerbose {
			color.Yellow("  Suggestion: %s\n", issue.Suggestion)
		}
	}
}
