package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scanner finds all Go source files in a repository
type Scanner struct {
	repoPath    string
	excludeDirs map[string]bool
	skipTests   bool
}

// NewScanner creates a new scanner for the given repository path
func NewScanner(repoPath string, skipTests bool) *Scanner {
	excludeDirs := map[string]bool{
		"vendor":        true,
		"testdata":      true,
		".git":          true,
		".svn":          true,
		".hg":           true,
		"node_modules":  true,
		"__pycache__":   true,
		".idea":         true,
		".vscode":       true,
		"dist":          true,
		"build":         true,
		"bin":           true,
		".cache":        true,
	}

	return &Scanner{
		repoPath:    repoPath,
		excludeDirs: excludeDirs,
		skipTests:   skipTests,
	}
}

// Scan walks the repository and returns all Go source files
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Repository: s.repoPath,
		ScanTime:   time.Now().Format(time.RFC3339),
		Files:      []FileInfo{},
		Statistics: ScanStatistics{
			ByExtension: make(map[string]int),
		},
	}

	dirsScanned := 0
	dirsExcluded := 0

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files/dirs we can't access
		}

		// Get relative path from repo root
		relPath, err := filepath.Rel(s.repoPath, path)
		if err != nil {
			relPath = path
		}

		// Skip excluded directories
		if info.IsDir() {
			dirName := filepath.Base(path)

			// Skip hidden directories (start with .)
			if strings.HasPrefix(dirName, ".") && dirName != "." {
				dirsExcluded++
				return filepath.SkipDir
			}

			// Skip directories starting with _
			if strings.HasPrefix(dirName, "_") {
				dirsExcluded++
				return filepath.SkipDir
			}

			// Skip excluded directory names
			if s.excludeDirs[dirName] {
				dirsExcluded++
				return filepath.SkipDir
			}

			dirsScanned++
			return nil
		}

		// Only process .go files
		ext := filepath.Ext(path)
		if ext != ".go" {
			return nil
		}

		// Optionally skip test files
		if s.skipTests && strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		// Add file to results
		result.Files = append(result.Files, FileInfo{
			Path:      relPath,
			Size:      info.Size(),
			Extension: ext,
		})

		// Update statistics
		result.Statistics.TotalFiles++
		result.Statistics.ByExtension[ext]++
		result.Statistics.TotalSizeBytes += info.Size()

		return nil
	})

	if err != nil {
		return nil, err
	}

	result.Statistics.DirectoriesScanned = dirsScanned
	result.Statistics.DirectoriesExcluded = dirsExcluded

	return result, nil
}

// GetFilePaths returns just the file paths for downstream processing
func (s *Scanner) GetFilePaths(result *ScanResult) []string {
	paths := make([]string, len(result.Files))
	for i, f := range result.Files {
		paths[i] = filepath.Join(s.repoPath, f.Path)
	}
	return paths
}
