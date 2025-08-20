package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DetectPipelineFiles recursively discovers pipeline files in the given path
func DetectPipelineFiles(path string) ([]string, error) {
	// Check if the path exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, err
	}

	// If the path is a file, return it directly
	if !info.IsDir() {
		return []string{path}, nil
	}

	// If the path is a directory, walk through it and discover pipeline files
	var files []string
	err = filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && isPipelineFile(filePath) {
			files = append(files, filePath)
		}

		return nil
	})

	return files, err
}

// isPipelineFile checks if a file is a pipeline file based on its name and extension
func isPipelineFile(path string) bool {
	fileName := strings.ToLower(filepath.Base(path))

	// Check for YAML files
	if strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml") {
		return true
	}

	// Check for Jenkinsfiles
	if fileName == "jenkinsfile" {
		return true
	}

	// Check for files with "pipeline" in their name
	if strings.Contains(fileName, "pipeline") {
		return true
	}

	return false
}

// FilterFiles filters a slice of file paths based on a list of exclude patterns.
// Exclude patterns can be either 1-based indices or full file paths.
func FilterFiles(files []string, exclude []string) []string {
	if len(exclude) == 0 {
		return files
	}

	excludedMap := make(map[string]bool)
	for _, e := range exclude {
		// Try to parse as an index
		var index int
		_, err := fmt.Sscanf(e, "%d", &index)
		if err == nil && index > 0 && index <= len(files) {
			excludedMap[filepath.Clean(files[index-1])] = true
		} else {
			// Treat as a file path, clean it for consistent comparison
			excludedMap[filepath.Clean(e)] = true
		}
	}

	var filteredFiles []string
	for _, file := range files {
		if !excludedMap[filepath.Clean(file)] {
			filteredFiles = append(filteredFiles, file)
		}
	}
	return filteredFiles
}
