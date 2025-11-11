package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
	systemPrompt = "You are a DevSecOps AI assistant that deeply analyzes CI/CD pipelines for logic, security, and configuration issues."
	userPrompt   = `Analyze the following CI/CD pipeline configuration(s).
Identify any of the following:

1. Security vulnerabilities (secrets exposure, unpinned versions, unsafe scripts, OAuth misuse)
2. Logical issues (incorrect job order, missing test gates, unsafe deploy triggers)
3. Best practice violations (unversioned dependencies, missing approval steps, excessive permissions)
4. Optimization suggestions.

Return only JSON in this exact structure:
{
"summary": "brief overall summary",
"issues": [
{
"type": "Security | Logic | BestPractice | Optimization",
"severity": "HIGH | MEDIUM | LOW",
"file": "<filename>",
"line": "<approx line number>",
"description": "<what is wrong>",
"suggestion": "<how to fix it>"
}
]
}

If no issues found, return:
{ "summary": "No issues found. The pipeline follows best practices.", "issues": [] }`
)

// GeminiRequest represents the request to the Gemini API
type GeminiRequest struct {
	Contents          []Content `json:"contents"`
	SystemInstruction Content   `json:"system_instruction"`
}

// Content represents a part of the request content
type Content struct {
	Parts []Part `json:"parts"`
}

// Part represents a text part of the content
type Part struct {
	Text string `json:"text"`
}

// GeminiResponse represents the response from the Gemini API
type GeminiResponse struct {
	Candidates []Candidate `json:"candidates"`
}

// Candidate represents a candidate response from the API
type Candidate struct {
	Content Content `json:"content"`
}

// AIResponse represents the structured JSON response from the AI
type AIResponse struct {
	Summary string  `json:"summary"`
	Issues  []Issue `json:"issues"`
}

// Issue represents a single issue found by the AI
type Issue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

// AnalyzePipeline sends the pipeline content to the Gemini API for analysis
func AnalyzePipeline(apiKey, content string) (*AIResponse, error) {
	reqBody := GeminiRequest{
		SystemInstruction: Content{
			Parts: []Part{{Text: systemPrompt}},
		},
		Contents: []Content{
			{
				Parts: []Part{
					{Text: userPrompt},
					{Text: content},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", geminiAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Gemini API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var geminiResp GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no content in Gemini API response")
	}

	aiResponseText := geminiResp.Candidates[0].Content.Parts[0].Text

	// Extract JSON from markdown code block if present
	if strings.HasPrefix(aiResponseText, "```json") && strings.HasSuffix(aiResponseText, "```") {
		aiResponseText = strings.TrimPrefix(aiResponseText, "```json\n")
		aiResponseText = strings.TrimSuffix(aiResponseText, "\n```")
	} else if strings.HasPrefix(aiResponseText, "```") && strings.HasSuffix(aiResponseText, "```") {
		// Handle cases where "json" might be missing from the markdown block
		aiResponseText = strings.TrimPrefix(aiResponseText, "```\n")
		aiResponseText = strings.TrimSuffix(aiResponseText, "\n```")
	}

	var aiResp AIResponse
	if err := json.Unmarshal([]byte(aiResponseText), &aiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AI response JSON: %w\nRaw response: %s", err, aiResponseText)
	}

	return &aiResp, nil
}

// ValidateAPIKey performs a lightweight call to the Gemini API to validate the API key.
func ValidateAPIKey(apiKey string) error {
	// Use a simple request that doesn't require complex input, e.g., listing models
	// Note: The actual endpoint for listing models might be different or require specific permissions.
	// For simplicity, we'll use a dummy request to the generateContent endpoint with minimal content.
	reqBody := GeminiRequest{
		SystemInstruction: Content{
			Parts: []Part{{Text: "You are a helpful assistant."}},
		},
		Contents: []Content{
			{
				Parts: []Part{
					{Text: "hello"},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal validation request: %w", err)
	}

	req, err := http.NewRequest("POST", geminiAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Gemini API validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Gemini API key validation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
