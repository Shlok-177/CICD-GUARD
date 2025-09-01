package rules

import (
	"fmt"
	"regexp"
	"strings"

	"cicd-guard/detector"
	"cicd-guard/types"
)

// checkHardcodedSecret checks for hardcoded secrets
func checkHardcodedSecret(filePath string, content string, lineNum int, line string) []types.Finding {
	// Extract the secret value for context
	secretMatch := regexp.MustCompile(`['"]([^'"]+)['"]`)
	matches := secretMatch.FindStringSubmatch(line)

	secretValue := ""
	if len(matches) > 1 {
		secretValue = matches[1]
	}

	d := detector.NewContextAwareDetector(4.0)
	finding := d.Evaluate(filePath, content, lineNum, line, secretValue, false)
	if finding == nil {
		return nil
	}
	if finding.Message == "" {
		finding.Message = "Hardcoded secret detected"
	}
	return []types.Finding{*finding}
}

// checkUnpinnedAction checks for unpinned GitHub Actions
func checkUnpinnedAction(filePath string, content string, lineNum int, line string) []types.Finding {
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
func checkEchoSecret(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "Echo statement might expose sensitive information",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkExposedSecretReference checks for exposed secret references
func checkExposedSecretReference(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "Secret reference exposed via echo - this could leak sensitive data",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkGenericSecret extracts the matched secret for context
func checkGenericSecret(filePath string, content string, lineNum int, line string) []types.Finding {
	// Use context-aware detector to decide severity and ignore false positives
	d := detector.NewContextAwareDetector(4.0)
	// Extract a likely secret-like token
	candidate := extractCandidateToken(line)
	finding := d.Evaluate(filePath, content, lineNum, line, candidate, false)
	if finding == nil {
		return nil
	}
	if finding.Message == "" {
		finding.Message = "Secret detected"
	}
	return []types.Finding{*finding}
}

// checkHighEntropySecret checks for generic high-entropy secrets
func checkHighEntropySecret(filePath string, content string, lineNum int, line string) []types.Finding {
	// Evaluate with entropy and context awareness
	d := detector.NewContextAwareDetector(4.0)
	candidate := extractCandidateToken(line)
	finding := d.Evaluate(filePath, content, lineNum, line, candidate, true)
	if finding == nil {
		return nil
	}
	if finding.Message == "" {
		finding.Message = "High-entropy string detected - potential secret"
	}
	return []types.Finding{*finding}
}

// checkGenericMisconfiguration provides the line as context for misconfigurations
func checkGenericMisconfiguration(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium, // Severity is set by the rule definition in engine.go
			Message:  "Potential misconfiguration detected",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkGitLabInsecureTrigger checks for GitLab CI jobs without only/except
func checkGitLabInsecureTrigger(filePath string, content string, lineNum int, line string) []types.Finding {
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
func checkJenkinsPlaintextCredentials(filePath string, content string, lineNum int, line string) []types.Finding {
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

// checkGitHubPullRequestTargetPermissions checks for pull_request_target without explicit permissions
func checkGitHubPullRequestTargetPermissions(filePath string, content string, lineNum int, line string) []types.Finding {
	lines := strings.Split(content, "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return nil
	}

	// Find the start of the 'on: pull_request_target:' block
	// This check assumes the regex in engine.go has already matched 'pull_request_target'.
	// We need to look for 'permissions:' within the scope of this trigger.

	// Find the indentation of the 'pull_request_target' line
	targetLineIdx := lineNum - 1
	targetIndentation := len(lines[targetLineIdx]) - len(strings.TrimLeft(lines[targetLineIdx], " "))

	foundPermissions := false
	// Look for 'permissions:' in subsequent lines at a higher indentation
	for i := targetLineIdx + 1; i < len(lines); i++ {
		currentLine := lines[i]
		trimmedLine := strings.TrimSpace(currentLine)
		if trimmedLine == "" {
			continue
		}

		indentation := len(currentLine) - len(strings.TrimLeft(currentLine, " "))

		if indentation <= targetIndentation && !strings.HasPrefix(trimmedLine, "#") {
			// We've moved out of the 'pull_request_target' block or to a sibling/parent key
			break
		}

		if strings.HasPrefix(trimmedLine, "permissions:") {
			foundPermissions = true
			break
		}
	}

	if !foundPermissions {
		return []types.Finding{
			{
				Severity: types.SeverityHigh,
				Message:  "GitHub Actions 'pull_request_target' without explicit permissions",
				Context:  strings.TrimSpace(lines[targetLineIdx]),
			},
		}
	}
	return nil
}

// checkJenkinsInputWithoutTimeout checks for Jenkins 'input' steps without a timeout
func checkJenkinsInputWithoutTimeout(filePath string, content string, lineNum int, line string) []types.Finding {
	lines := strings.Split(content, "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return nil
	}

	// Find the start of the 'input' step block
	inputLineIdx := lineNum - 1
	inputIndentation := len(lines[inputLineIdx]) - len(strings.TrimLeft(lines[inputLineIdx], " "))

	foundTimeout := false
	// Look for 'timeout:' in subsequent lines within the 'input' block
	for i := inputLineIdx + 1; i < len(lines); i++ {
		currentLine := lines[i]
		trimmedLine := strings.TrimSpace(currentLine)
		if trimmedLine == "" {
			continue
		}

		indentation := len(currentLine) - len(strings.TrimLeft(currentLine, " "))

		if indentation <= inputIndentation && !strings.HasPrefix(trimmedLine, "#") {
			// We've moved out of the 'input' block or to a sibling/parent key
			break
		}

		if strings.HasPrefix(trimmedLine, "timeout:") {
			foundTimeout = true
			break
		}
	}

	if !foundTimeout {
		return []types.Finding{
			{
				Severity: types.SeverityMedium,
				Message:  "Jenkins 'input' step without timeout",
				Context:  strings.TrimSpace(lines[inputLineIdx]),
			},
		}
	}
	return nil
}

// checkCurlToBash checks for insecure curl to bash pipes
func checkCurlToBash(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "Insecure curl to bash pipe detected",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkGitHubSudoRun checks for 'sudo' in GitHub Actions 'run' steps
func checkGitHubSudoRun(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityMedium,
			Message:  "GitHub Actions 'run' step uses 'sudo' - consider if elevated privileges are necessary",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkAzureSystemAccessToken checks for direct usage of System.AccessToken in Azure Pipelines scripts
func checkAzureSystemAccessToken(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "Direct usage of System.AccessToken detected - consider using specific permissions or service connections",
			Context:  strings.TrimSpace(line),
		},
	}
}

// checkJenkinsUnsafeShellStep checks for unsafe shell steps in Jenkins pipelines
func checkJenkinsUnsafeShellStep(filePath string, content string, lineNum int, line string) []types.Finding {
	return []types.Finding{
		{
			Severity: types.SeverityHigh,
			Message:  "Unsafe shell step detected - ensure proper sanitization of user-controlled input",
			Context:  strings.TrimSpace(line),
		},
	}
}

// extractCandidateToken tries to pull out a secret-like token for entropy analysis.
func extractCandidateToken(line string) string {
	trimmed := strings.TrimSpace(line)
	// Prefer quoted content of reasonable length
	if m := regexp.MustCompile(`['\"]([A-Za-z0-9_\-\+/=]{8,})['\"]`).FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	// Otherwise take the longest plausible token (20+)
	tokens := regexp.MustCompile(`[A-Za-z0-9_\-\+/=]{20,}`).FindAllString(trimmed, -1)
	longest := ""
	for _, t := range tokens {
		if len(t) > len(longest) {
			longest = t
		}
	}
	if longest != "" {
		return longest
	}
	return trimmed
}
