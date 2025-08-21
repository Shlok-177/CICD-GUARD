package rules

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"cicd-guard/types"
	"cicd-guard/utils"

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
	AppliesTo   []utils.Platform
}

// RunRules runs all registered rules against the file content
func (e *Engine) RunRules(filePath, content string) []types.Finding {
	var findings []types.Finding
	detectedPlatform := utils.DetectPipelinePlatform(filePath)

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		customRuleMatched := false

		// Run custom rules first
		for _, customRule := range e.customRules {
			pattern, err := regexp.Compile(customRule.Pattern)
			if err != nil {
				continue
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
				break
			}
		}

		// Run builtin rules only if no custom matched
		if !customRuleMatched {
			for _, rule := range e.rules {
				applies := false
				for _, p := range rule.AppliesTo {
					if p == detectedPlatform || p == utils.PlatformAll {
						applies = true
						break
					}
				}

				if applies && rule.Pattern.MatchString(line) {
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

// registerBuiltinRules registers all built-in security rules (deduplicated)
func (e *Engine) registerBuiltinRules() {
	seen := make(map[string]bool)

	candidateRules := []Rule{
		// GitHub Actions
		{
			Name:        "GitHub Actions Write-All Permissions",
			Description: "Warns if 'permissions: write-all' is used in GitHub Actions",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`permissions:\s*write-all`),
			Check:       checkGenericMisconfiguration,
			RuleID:      "GH002",
			AppliesTo:   []utils.Platform{utils.PlatformGitHub},
		},
		{
			Name:        "Unpinned GitHub Action",
			Description: "Detects unpinned GitHub Actions (using @main or @master)",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`uses:\s*[^@\s]+@(main|master)`),
			Check:       checkUnpinnedAction,
			RuleID:      "UNPINNED_ACTION",
			AppliesTo:   []utils.Platform{utils.PlatformGitHub},
		},

		// GitLab CI
		{
			Name:        "GitLab CI Hardcoded Master Branch",
			Description: "Warns if default branch is hardcoded as 'master' instead of 'main'",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)default_branch:\s*master`),
			Check:       checkGenericMisconfiguration,
			RuleID:      "GL001",
			AppliesTo:   []utils.Platform{utils.PlatformGitLab},
		},
		{
			Name:        "GitLab CI Job Without Only/Except",
			Description: "Detects GitLab CI jobs without 'only/except' for insecure triggering",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?m)^\s*script:`),
			Check:       checkGitLabInsecureTrigger,
			RuleID:      "GL002",
			AppliesTo:   []utils.Platform{utils.PlatformGitLab},
		},

		// Azure Pipelines
		{
			Name:        "Azure Pipelines Unpinned VM Image",
			Description: "Detects unpinned VM images in Azure Pipelines (e.g., 'windows-latest')",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`pool:\s*vmImage:\s*['"](windows-latest|ubuntu-latest|macos-latest)['"]`),
			Check:       checkGenericMisconfiguration,
			RuleID:      "AZ001",
			AppliesTo:   []utils.Platform{utils.PlatformAzure},
		},
		{
			Name:        "Azure Pipelines Inline Secret",
			Description: "Detects inline secrets in Azure Pipelines YAML (password: ...)",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)password:\s*(?:['"]([^'"]+)['"]|(\S+))`),
			Check:       checkGenericSecret,
			RuleID:      "AZ002",
			AppliesTo:   []utils.Platform{utils.PlatformAzure},
		},

		// Jenkins
		{
			Name:        "Jenkins Plaintext withCredentials",
			Description: "Warns on 'withCredentials' using plaintext in Jenkins",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`withCredentials\(\[\s*string\(credentialsId:\s*['"][^'"]+['"],\s*variable:\s*['"][^'"]+['"]\)\s*]\)`),
			Check:       checkJenkinsPlaintextCredentials,
			RuleID:      "JK001",
			AppliesTo:   []utils.Platform{utils.PlatformJenkins},
		},
		{
			Name:        "Jenkins Hardcoded Password in Groovy",
			Description: "Detects hardcoded passwords in Jenkins Groovy DSL",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`(?i)(def\s+\w+\s*=\s*['"](?:password|secret|token)[^'"]*['"]|env\.[A-Z_]+\s*=\s*['"](?:password|secret|token)[^'"]*['"])`),
			Check:       checkGenericSecret,
			RuleID:      "JK002",
			AppliesTo:   []utils.Platform{utils.PlatformJenkins},
		},

		// Secrets (Global)
		{
			Name:        "AWS Access Key ID",
			Description: "Detects AWS access keys (AKIA[0-9A-Z]{16})",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Check:       checkGenericSecret,
			RuleID:      "SEC001",
			AppliesTo:   []utils.Platform{utils.PlatformAll},
		},
		{
			Name:        "Azure Connection String",
			Description: "Detects Azure connection strings",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`),
			Check:       checkGenericSecret,
			RuleID:      "SEC002",
			AppliesTo:   []utils.Platform{utils.PlatformAzure, utils.PlatformAll},
		},
		{
			Name:        "GitHub Token",
			Description: "Detects GitHub tokens (ghp_...)",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Check:       checkGenericSecret,
			RuleID:      "SEC003",
			AppliesTo:   []utils.Platform{utils.PlatformGitHub, utils.PlatformAll},
		},
		{
			Name:        "Generic High-Entropy Secret",
			Description: "Detects generic high-entropy secrets (>=40 chars, random-looking)",
			Severity:    types.SeverityHigh,
			Pattern:     regexp.MustCompile(`[a-zA-Z0-9]{40,}`),
			Check:       checkHighEntropySecret,
			RuleID:      "SEC004",
			AppliesTo:   []utils.Platform{utils.PlatformAll},
		},

		// Miscellaneous
		{
			Name:        "Echo Secret",
			Description: "Detects echo statements that might expose secrets",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+['"][^'"]*(secret|key|token|password)[^'"]*['"]`),
			Check:       checkHardcodedSecret,
			RuleID:      "ECHO_SECRET",
			AppliesTo:   []utils.Platform{utils.PlatformAll},
		},
		{
			Name:        "Exposed Secret Reference",
			Description: "Detects exposed secret references via echo",
			Severity:    types.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)echo\s+\$?\{?secrets\.[^'"]*\}?`),
			Check:       checkExposedSecretReference,
			RuleID:      "EXPOSED_SECRET_REF",
			AppliesTo:   []utils.Platform{utils.PlatformAll},
		},
	}

	// Deduplicate by RuleID
	for _, r := range candidateRules {
		if !seen[r.RuleID] {
			e.rules = append(e.rules, r)
			seen[r.RuleID] = true
		}
	}
}
