package rules

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"cicd-guard/types"

	"gopkg.in/yaml.v3"
)

// Engine runs security rules against CI/CD files
type Engine struct {
	rules       []Rule
	customRules []types.CustomRule
}

// NewEngine creates a new rules engine
func NewEngine() *Engine {
	engine := &Engine{}
	engine.registerBuiltinRules()
	return engine
}

// LoadCustomRules loads custom rules from a YAML file
func (e *Engine) LoadCustomRules(rulesFile string) error {
	if rulesFile == "" {
		return nil
	}

	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var customRules types.CustomRules
	if err := yaml.Unmarshal(data, &customRules); err != nil {
		return fmt.Errorf("failed to parse rules file: %w", err)
	}

	e.customRules = customRules.Rules
	return nil
}

// Rule represents a security rule
type Rule struct {
	Name        string
	Description string
	Severity    types.Severity
	Pattern     *regexp.Regexp
	Check       func(content string, lineNum int, line string) []types.Finding
	RuleID      string
}

// RunRules runs all registered rules against the file content
func (e *Engine) RunRules(filePath, content string) []types.Finding {
	var findings []types.Finding

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		customRuleMatched := false

		// Run custom rules FIRST (they take priority)
		for _, customRule := range e.customRules {
			pattern, err := regexp.Compile(customRule.Pattern)
			if err != nil {
				continue // Skip invalid patterns
			}

			if pattern.MatchString(line) {
				finding := types.Finding{
					Severity: customRule.Severity,
					Message:  customRule.Message,
					File:     filePath,
					Line:     lineNum,
					Rule:     customRule.Description,
					RuleID:   customRule.ID,
					Context:  strings.TrimSpace(line),
				}
				findings = append(findings, finding)
				customRuleMatched = true
				break // Only use the first matching custom rule
			}
		}

		// Run builtin rules only if no custom rule matched
		if !customRuleMatched {
			for _, rule := range e.rules {
				if rule.Pattern.MatchString(line) {
					ruleFindings := rule.Check(content, lineNum, line)
					for i := range ruleFindings {
						ruleFindings[i].File = filePath
						ruleFindings[i].Line = lineNum
						ruleFindings[i].Rule = rule.Name
						ruleFindings[i].RuleID = rule.RuleID
					}
					findings = append(findings, ruleFindings...)
				}
			}
		}
	}

	return findings
}

// registerBuiltinRules registers all built-in security rules
func (e *Engine) registerBuiltinRules() {
	e.rules = []Rule{
		{
			Name:        "Hardcoded AWS Secret Key",
			Description: "Detects hardcoded AWS secret keys",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"][^'"]{20,}['"]`),
			Check:       checkHardcodedSecret,
			RuleID:      "AWS_SECRET_KEY",
		},
		{
			Name:        "Hardcoded AWS Access Key",
			Description: "Detects hardcoded AWS access keys",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)aws_access_key_id\s*=\s*['"][^'"]{20,}['"]`),
			Check:       checkHardcodedSecret,
			RuleID:      "AWS_ACCESS_KEY",
		},
		{
			Name:        "Hardcoded API Token",
			Description: "Detects hardcoded API tokens",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)(api_key|token|password)\s*=\s*['"][^'"]{10,}['"]`),
			Check:       checkHardcodedSecret,
			RuleID:      "HARDCODED_API_TOKEN",
		},
		{
			Name:        "Unpinned GitHub Action",
			Description: "Detects unpinned GitHub Actions (using @main or @master)",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`uses:\s*[^@\s]+@(main|master)`),
			Check:       checkUnpinnedAction,
			RuleID:      "UNPINNED_ACTION",
		},
		{
			Name:        "Echo Secret",
			Description: "Detects echo statements that might expose secrets",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+['"][^'"]*(secret|key|token|password)[^'"]*['"]`),
			Check:       checkHardcodedSecret,
			RuleID:      "ECHO_SECRET",
		},
		{
			Name:        "Exposed Secret Reference",
			Description: "Detects exposed secret references via echo",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+\$?\{?secrets\.[^'"]*\}?`),
			Check:       checkExposedSecretReference,
			RuleID:      "EXPOSED_SECRET_REF",
		},
	}
}
