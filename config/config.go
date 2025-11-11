package config

import (
	"cicd-guard/ai"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Config stores the application configuration
type Config struct {
	GeminiAPIKey string `json:"gemini_api_key"`
}

// GetConfigPath returns the path to the configuration file
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cicd-guard", "config.json"), nil
}

// ReadConfig reads the configuration from the file
func ReadConfig() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &Config{}, nil // Return empty config if file doesn't exist
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig saves the configuration to the file
func SaveConfig(config *Config) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configPath, data, 0600)
}

// GetAPIKey prompts the user for the API key if it's not in the config
func GetAPIKey() (string, error) {
	config, err := ReadConfig()
	if err != nil {
		return "", err
	}

	// If a key is already stored, validate it first
	if config.GeminiAPIKey != "" {
		if err := ai.ValidateAPIKey(config.GeminiAPIKey); err == nil {
			return config.GeminiAPIKey, nil // Stored key is valid, reuse it
		}
		// If stored key is invalid, fall through to prompt for a new one
		fmt.Println("Stored Gemini API key is invalid. Please enter a new one.")
	}

	var apiKey string
	for {
		fmt.Print("Please enter your Gemini API key: ")
		fmt.Scanln(&apiKey)

		if err := ai.ValidateAPIKey(apiKey); err != nil {
			fmt.Printf("Invalid Gemini API key: %v. Please try again.\n", err)
			continue
		}

		config.GeminiAPIKey = apiKey
		if err := SaveConfig(config); err != nil {
			return "", fmt.Errorf("failed to save API key: %w", err)
		}
		return apiKey, nil
	}
}
