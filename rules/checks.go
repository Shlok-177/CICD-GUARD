package rules

import (
	"fmt"
	"regexp"
	"strings"

	"cicd-guard/types"
)

// checkHardcodedSecret checks for hardcoded secrets
func checkHardcodedSecret(content string, lineNum int, line string) []types.Finding {
	// Extract the secret value for context
	secretMatch := regexp.MustCompile(`['"]([^'"]+)['"]`)
	matches := secretMatch.FindStringSubmatch(line)

	context := ""
	if len(matches) > 1 {
		secret := matches[1]
		if len(secret) > 10 {
			context = secret[:10] + "..."
		} else {
			context = secret
		}
	}

	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "Hardcoded secret detected",
			Context:  context,
		},
	}
}

// checkUnpinnedAction checks for unpinned GitHub Actions
func checkUnpinnedAction(content string, lineNum int, line string) []types.Finding {
	// Extract the action name for context
	actionMatch := regexp.MustCompile(`uses:\s*([^@\s]+)@(main|master)`)
	matches := actionMatch.FindStringSubmatch(line)

	context := ""
	if len(matches) > 2 {
		context = fmt.Sprintf("Action: %s@%s", matches[1], matches[2])
	}

	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "Unpinned action detected - consider using a specific version or SHA",
			Context:  context,
		},
	}
}

// checkEchoSecret checks for echo statements that might expose secrets
func checkEchoSecret(content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "Echo statement might expose sensitive information",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkExposedSecretReference checks for exposed secret references
func checkExposedSecretReference(content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "Secret reference exposed via echo - this could leak sensitive data",
			Context:  strings.TrimSpace(line),
		},
	}
}
