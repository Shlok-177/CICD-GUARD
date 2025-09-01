package detector

import (
	"path/filepath"
	"regexp"
	"strings"

	"cicd-guard/types"
)

// ContextAwareDetector performs entropy and context checks to reduce false positives.
type ContextAwareDetector struct {
	entropyThreshold float64
}

func NewContextAwareDetector(entropyThreshold float64) *ContextAwareDetector {
	if entropyThreshold <= 0 {
		entropyThreshold = 4.0
	}
	return &ContextAwareDetector{entropyThreshold: entropyThreshold}
}

// Evaluate examines a candidate secret within a specific line and file context.
// If requireEntropy is true, the candidate must exceed the entropy threshold; otherwise entropy is not enforced.
// Returns nil if the candidate should be ignored.
func (d *ContextAwareDetector) Evaluate(filePath, content string, lineNum int, line, candidate string, requireEntropy bool) *types.Finding {
	trimmed := strings.TrimSpace(line)

	// Ignore comments and documentation-like files
	if isCommentLine(trimmed) || isDocumentationFile(filePath) || isTestDataFile(filePath) {
		return nil
	}

	// Entropy check (optional)
	if requireEntropy {
		if ComputeShannonEntropy(candidate) < d.entropyThreshold {
			return nil
		}
	}

	// Context keywords in line
	hasKeyword := containsContextKeyword(trimmed)

	// Nearby YAML/CI context indicators
	strongContext := hasKeyword || hasNearbyContext(content, lineNum)

	severity := types.SeverityMedium
	if strongContext {
		severity = types.SeverityHigh
	}

	// Lower severity if looks like sample/test within file path, but not comments-only
	if looksLikeTestPath(filePath) {
		// As per requirements, test data should be ignored
		return nil
	}

	return &types.Finding{
		Severity: severity,
		Message:  "Context-aware secret candidate detected",
		Context:  strings.TrimSpace(line),
	}
}

var keywordRe = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|credential)`) // simple heuristic

func containsContextKeyword(s string) bool {
	return keywordRe.MatchString(s)
}

func hasNearbyContext(content string, lineNum int) bool {
	if lineNum <= 0 {
		return false
	}
	lines := strings.Split(content, "\n")
	start := lineNum - 3
	if start < 0 {
		start = 0
	}
	end := lineNum + 2
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// Common CI blocks
		if strings.HasPrefix(t, "env:") || strings.HasPrefix(t, "secrets:") || strings.HasPrefix(t, "variables:") || strings.HasPrefix(t, "credentials:") {
			return true
		}
		// Inline indicators
		if containsContextKeyword(t) {
			return true
		}
	}
	return false
}

func isCommentLine(trimmed string) bool {
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "-- ") {
		return true
	}
	// YAML inline comment: if everything before # is empty/whitespace
	if idx := strings.Index(trimmed, "#"); idx == 0 {
		return true
	}
	return false
}

func isDocumentationFile(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".rst") || strings.HasSuffix(lower, ".adoc") || strings.HasSuffix(lower, ".txt") {
		return true
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.Contains(base, "readme") || strings.Contains(base, "changelog") {
		return true
	}
	return false
}

func isTestDataFile(path string) bool {
	lower := strings.ToLower(path)
	if strings.Contains(lower, string(filepath.Separator)+"test"+string(filepath.Separator)) || strings.Contains(lower, "tests") || strings.Contains(lower, "testdata") || strings.Contains(lower, "fixtures") {
		return true
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.Contains(base, "example") || strings.Contains(base, "sample") || strings.Contains(base, "fixture") {
		return true
	}
	return false
}

func looksLikeTestPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "test") || strings.Contains(lower, "example") || strings.Contains(lower, "sample") || strings.Contains(lower, "fixture")
}
