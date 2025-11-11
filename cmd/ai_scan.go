package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cicd-guard/ai"
	"cicd-guard/config"
	"cicd-guard/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const maxContentSize = 10 * 1024 // 10KB

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

		var allIssues []ai.Issue
		var overallSummary string

		for _, file := range pipelineFiles {
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
			printFormattedOutput(overallSummary, allIssues)
		}
	},
}

func init() {
	rootCmd.AddCommand(aiScanCmd)
	aiScanCmd.Flags().Bool("json", false, "Output the raw Gemini JSON response.")
	aiScanCmd.PersistentFlags().StringVarP(&path, "path", "p", ".", "Path to scan (default: current directory)")
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
		color.Yellow("  Suggestion: %s\n", issue.Suggestion)
	}
}
