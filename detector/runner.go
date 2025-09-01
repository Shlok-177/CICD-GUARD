package detector

import (
	"fmt"
	"os"
	"strings"

	"cicd-guard/ignore"
	"cicd-guard/types"
)

// ScanOptions controls context-aware secret scanning behavior.
type ScanOptions struct {
	EntropyThreshold float64
}

// RunContextAwareSecrets scans provided files and returns context-aware secret findings.
// It respects .cicd-guard-ignore via the ignore.Manager.
func RunContextAwareSecrets(files []string, opts ScanOptions) ([]types.Finding, error) {
	ig := ignore.Load(".")
	detector := NewContextAwareDetector(opts.EntropyThreshold)
	var results []types.Finding

	for _, file := range files {
		if ig != nil && ig.ShouldIgnoreFile(file) {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file, err)
		}
		content := string(data)
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			// Candidates: quick regex-based prefilter similar to existing rules
			// 1) AWS Access Key ID
			if aws := awsAccessKey(line); aws != "" {
				if f := detector.Evaluate(file, content, i+1, line, aws, false); f != nil {
					f.RuleID = "SEC001"
					f.Rule = "AWS Access Key ID"
					f.Message = "Possible AWS Key detected"
					f.File = file
					f.Line = i + 1
					if ig != nil && ig.ShouldIgnoreLine(f.Context) {
						continue
					}
					results = append(results, *f)
				}
			}
			// 2) GitHub Token
			if gh := githubToken(line); gh != "" {
				if f := detector.Evaluate(file, content, i+1, line, gh, false); f != nil {
					f.RuleID = "SEC003"
					f.Rule = "GitHub Token"
					f.Message = "Possible GitHub Token detected"
					f.File = file
					f.Line = i + 1
					if ig != nil && ig.ShouldIgnoreLine(f.Context) {
						continue
					}
					results = append(results, *f)
				}
			}
			// 3) Azure connection string (key present inline)
			if az := azureConnString(line); az != "" {
				if f := detector.Evaluate(file, content, i+1, line, az, false); f != nil {
					f.RuleID = "SEC002"
					f.Rule = "Azure Connection String"
					f.Message = "Possible Azure credential detected"
					f.File = file
					f.Line = i + 1
					if ig != nil && ig.ShouldIgnoreLine(f.Context) {
						continue
					}
					results = append(results, *f)
				}
			}
			// 4) Generic high-entropy candidates from long tokens
			if token := longestHighEntropyToken(line); token != "" {
				if f := detector.Evaluate(file, content, i+1, line, token, true); f != nil {
					f.RuleID = "SEC004"
					f.Rule = "Generic High-Entropy Secret"
					f.Message = "High-entropy string detected - potential secret"
					f.File = file
					f.Line = i + 1
					if ig != nil && ig.ShouldIgnoreLine(f.Context) {
						continue
					}
					results = append(results, *f)
				}
			}
		}
	}
	return results, nil
}

// Lightweight recognizers aligned with builtin patterns
func awsAccessKey(line string) string {
	// AKIA followed by 16 uppercase alphanumerics
	if m := awsKeyRe.FindString(line); m != "" {
		return m
	}
	return ""
}

func githubToken(line string) string {
	if m := ghTokenRe.FindString(line); m != "" {
		return m
	}
	return ""
}

func azureConnString(line string) string {
	if m := azureConnRe.FindString(line); m != "" {
		return m
	}
	return ""
}

func longestHighEntropyToken(line string) string {
	tokens := longTokenRe.FindAllString(line, -1)
	longest := ""
	for _, t := range tokens {
		if len(t) > len(longest) {
			longest = t
		}
	}
	return longest
}
