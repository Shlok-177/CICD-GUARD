package rules

import (
	"bufio"
	"regexp"
	"strings"

	"cicd-guard/types"
)

// Engine runs security rules against CI/CD files
type Engine struct {
	rules []Rule
}

// NewEngine creates a new rules engine
func NewEngine() *Engine {
	engine := &Engine{}
	engine.registerRules()
	return engine
}

// Rule represents a security rule
type Rule struct {
	Name        string
	Description string
	Severity    types.Severity
	Pattern     *regexp.Regexp
	Check       func(content string, lineNum int, line string) []types.Finding
}

// RunRules runs all registered rules against the file content
func (e *Engine) RunRules(filePath, content string) []types.Finding {
	var findings []types.Finding

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range e.rules {
			if rule.Pattern.MatchString(line) {
				ruleFindings := rule.Check(content, lineNum, line)
				for i := range ruleFindings {
					ruleFindings[i].File = filePath
					ruleFindings[i].Line = lineNum
					ruleFindings[i].Rule = rule.Name
				}
				findings = append(findings, ruleFindings...)
			}
		}
	}

	return findings
}

// registerRules registers all security rules
func (e *Engine) registerRules() {
	e.rules = []Rule{
		{
			Name:        "Hardcoded AWS Secret Key",
			Description: "Detects hardcoded AWS secret keys",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"][^'"]{20,}['"]`),
			Check:       checkHardcodedSecret,
		},
		{
			Name:        "Hardcoded AWS Access Key",
			Description: "Detects hardcoded AWS access keys",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)aws_access_key_id\s*=\s*['"][^'"]{20,}['"]`),
			Check:       checkHardcodedSecret,
		},
		{
			Name:        "Hardcoded API Token",
			Description: "Detects hardcoded API tokens",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)(api_key|token|password)\s*=\s*['"][^'"]{10,}['"]`),
			Check:       checkHardcodedSecret,
		},
		{
			Name:        "Unpinned GitHub Action",
			Description: "Detects unpinned GitHub Actions (using @main or @master)",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`uses:\s*[^@\s]+@(main|master)`),
			Check:       checkUnpinnedAction,
		},
		{
			Name:        "Echo Secret",
			Description: "Detects echo statements that might expose secrets",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+['"][^'"]*(secret|key|token|password)[^'"]*['"]`),
			Check:       checkHardcodedSecret,
		},
		{
			Name:        "Exposed Secret Reference",
			Description: "Detects exposed secret references via echo",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+\$?\{?secrets\.[^'"]*\}?`),
			Check:       checkExposedSecretReference,
		},
	}
}
