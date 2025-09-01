package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreManager loads and checks ignore patterns.
type IgnoreManager struct {
	fileGlobs   []string
	lineSubstrs []string
}

// LoadIgnore reads patterns from .cicd-guard-ignore in the provided root path, if present.
func LoadIgnore(root string) *IgnoreManager {
	ig := &IgnoreManager{}
	path := filepath.Join(root, ".cicd-guard-ignore")
	f, err := os.Open(path)
	if err != nil {
		return ig
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "file:") {
			ig.fileGlobs = append(ig.fileGlobs, strings.TrimSpace(strings.TrimPrefix(line, "file:")))
		} else if strings.HasPrefix(line, "ignore:") {
			ig.lineSubstrs = append(ig.lineSubstrs, strings.TrimSpace(strings.TrimPrefix(line, "ignore:")))
		} else {
			// Backward-compatible: treat as file glob
			ig.fileGlobs = append(ig.fileGlobs, line)
		}
	}
	return ig
}

// ShouldIgnoreFile returns true if the file matches any glob pattern.
func (ig *IgnoreManager) ShouldIgnoreFile(path string) bool {
	for _, g := range ig.fileGlobs {
		if ok, _ := filepath.Match(g, filepath.Base(path)); ok {
			return true
		}
		if strings.Contains(path, g) { // simple contains fallback
			return true
		}
	}
	return false
}

// ShouldIgnoreLine returns true if the line contains any ignored substring.
func (ig *IgnoreManager) ShouldIgnoreLine(line string) bool {
	for _, s := range ig.lineSubstrs {
		if s != "" && strings.Contains(line, s) {
			return true
		}
	}
	return false
}
