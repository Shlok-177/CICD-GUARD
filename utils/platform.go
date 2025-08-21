package utils

import (
	"path/filepath"
	"strings"
)

// Platform represents a CI/CD platform
type Platform string

const (
	PlatformGitHub  Platform = "github"
	PlatformGitLab  Platform = "gitlab"
	PlatformAzure   Platform = "azure"
	PlatformJenkins Platform = "jenkins"
	PlatformAll     Platform = "all" // For rules that apply to all platforms
	PlatformUnknown Platform = "unknown"
)

// DetectPipelinePlatform detects the CI/CD platform based on the file path.
func DetectPipelinePlatform(filePath string) Platform {
	base := filepath.Base(filePath)
	// Use filepath.ToSlash to ensure consistent path separators for string matching
	// This is important for cross-platform compatibility, especially on Windows.
	normalizedPath := filepath.ToSlash(filePath)

	switch {
	case strings.HasPrefix(normalizedPath, ".github/workflows/") || strings.Contains(normalizedPath, "/.github/workflows/"):
		return PlatformGitHub
	case base == ".gitlab-ci.yml":
		return PlatformGitLab
	case strings.Contains(base, "azure-pipelines") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return PlatformAzure
	case base == "Jenkinsfile" || strings.HasSuffix(base, ".jenkins"):
		return PlatformJenkins
	default:
		return PlatformUnknown
	}
}
