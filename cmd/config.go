package cmd

import (
	"fmt"
	"os"

	"cicd-guard/ai"
	"cicd-guard/config"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage cicd-guard configuration, including API keys",
	Long:  `The config command allows you to manage various settings for cicd-guard, such as API keys.`,
}

func init() {
	rootCmd.AddCommand(configCmd)

	// Add subcommands for API key management
	configCmd.AddCommand(setAPIKeyCmd)
	configCmd.AddCommand(removeAPIKeyCmd)
	configCmd.AddCommand(showAPIKeyCmd)
}

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key",
	Short: "Set or update the Gemini API key",
	Long:  `This command allows you to set or update your Gemini API key. The key will be validated upon entry.`,
	Run: func(cmd *cobra.Command, args []string) {
		var apiKey string
		fmt.Print("Please enter your Gemini API key: ")
		fmt.Scanln(&apiKey)

		cfg, err := config.ReadConfig()
		if err != nil {
			color.Red("Error reading configuration: %v", err)
			os.Exit(1)
		}

		cfg.GeminiAPIKey = apiKey
		if err := config.SaveConfig(cfg); err != nil {
			color.Red("Error saving API key: %v", err)
			os.Exit(1)
		}

		// Validate the API key after saving
		if err := ai.ValidateAPIKey(apiKey); err != nil {
			color.Red("API key saved, but validation failed: %v", err)
			color.Yellow("Please ensure the API key is correct and has sufficient permissions/quota.")
			os.Exit(1)
		}

		color.Green("Gemini API key successfully set and validated.")
	},
}

var removeAPIKeyCmd = &cobra.Command{
	Use:   "remove-api-key",
	Short: "Remove the stored Gemini API key",
	Long:  `This command removes the Gemini API key stored locally.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.ReadConfig()
		if err != nil {
			color.Red("Error reading configuration: %v", err)
			os.Exit(1)
		}

		if cfg.GeminiAPIKey == "" {
			color.Yellow("No Gemini API key is currently stored.")
			return
		}

		cfg.GeminiAPIKey = ""
		if err := config.SaveConfig(cfg); err != nil {
			color.Red("Error removing API key: %v", err)
			os.Exit(1)
		}

		color.Green("Gemini API key successfully removed.")
	},
}

var showAPIKeyCmd = &cobra.Command{
	Use:   "show-api-key",
	Short: "Show if a Gemini API key is stored",
	Long:  `This command indicates whether a Gemini API key is currently stored locally. It does not display the key itself.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.ReadConfig()
		if err != nil {
			color.Red("Error reading configuration: %v", err)
			os.Exit(1)
		}

		if cfg.GeminiAPIKey != "" {
			color.Green("A Gemini API key is currently stored.")
		} else {
			color.Yellow("No Gemini API key is currently stored.")
		}
	},
}
