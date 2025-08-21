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

// checkGenericSecret extracts the matched secret for context
func checkGenericSecret(content string, lineNum int, line string) []types.Finding {
	// This function is called when a specific secret pattern is matched by the rule's regex.
	// The 'line' itself is the context.
	return []types.Finding{
		{
			Severity: types.SeverityHigh, // Severity is set by the rule definition in engine.go
			Message:  "Secret detected",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkHighEntropySecret checks for generic high-entropy secrets
func checkHighEntropySecret(content string, lineNum int, line string) []types.Finding {
	// The regex in engine.go already filters for length.
	// Additional entropy checks could be added here if needed, but for now,
	// just report the line as context.
	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "High-entropy string detected - potential secret",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkGenericMisconfiguration provides the line as context for misconfigurations
func checkGenericMisconfiguration(content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium, // Severity is set by the rule definition in engine.go
			Message:  "Potential misconfiguration detected",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkGitLabInsecureTrigger checks for GitLab CI jobs without only/except
func checkGitLabInsecureTrigger(content string, lineNum int, line string) []types.Finding {
	lines := strings.Split(content, "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return nil
	}

	// The line that matched the regex is 'lineNum' (1-indexed).
	// We need to find the job definition that this script belongs to.
	scriptLineIdx := lineNum - 1 // 0-indexed

	// Determine the indentation of the script line
	scriptIndentation := len(lines[scriptLineIdx]) - len(strings.TrimLeft(lines[scriptLineIdx], " "))

	jobStartLineIdx := -1
	// Iterate backwards from the line *before* the script line
	for i := scriptLineIdx - 1; i >= 0; i-- {
		currentLine := lines[i]
		trimmedLine := strings.TrimSpace(currentLine)
		if trimmedLine == "" {
			continue
		}

		indentation := len(currentLine) - len(strings.TrimLeft(currentLine, " "))

		// A job definition line typically ends with a colon and has an indentation
		// less than or equal to the script's parent, but greater than its own parent.
		// For a top-level job, indentation will be 0.
		if strings.HasSuffix(trimmedLine, ":") && indentation < scriptIndentation {
			jobStartLineIdx = i
			break
		}
	}

	if jobStartLineIdx == -1 {
		// Could not determine job start, or it's a top-level script without a clear job.
		// This might happen for very simple scripts not part of a named job.
		// For the purpose of this rule, we assume a job name exists.
		return nil
	}

	// Now, check for 'only:' or 'except:' within the identified job block.
	// The job block starts at jobStartLineIdx and ends before the next top-level key
	// or the end of the file. For simplicity, we'll check lines between jobStartLineIdx
	// and scriptLineIdx.
	foundTrigger := false
	for i := jobStartLineIdx; i < scriptLineIdx; i++ {
		currentLine := strings.TrimSpace(lines[i])
		if strings.HasPrefix(currentLine, "only:") || strings.HasPrefix(currentLine, "except:") {
			foundTrigger = true
			break
		}
	}

	if !foundTrigger {
		return []types.Finding{
			{
				Severity: types.SeverityMedium,
				Message:  "GitLab CI job might be insecurely triggered (missing 'only' or 'except')",
				Context:  strings.TrimSpace(lines[jobStartLineIdx]), // Context is the job definition line
			},
		}
	}
	return nil
}

// checkJenkinsPlaintextCredentials checks for plaintext credentials in withCredentials
func checkJenkinsPlaintextCredentials(content string, lineNum int, line string) []types.Finding {
	// The regex in engine.go attempts to find specific patterns.
	// This function provides the context.
	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "Jenkins 'withCredentials' using plaintext - sensitive data exposure risk",
			Context:  strings.TrimSpace(line),
		},
	}
}
