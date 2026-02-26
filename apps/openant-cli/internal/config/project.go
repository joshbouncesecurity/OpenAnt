package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Project holds metadata for an initialized project workspace.
type Project struct {
	Name           string `json:"name"`
	RepoURL        string `json:"repo_url,omitempty"`
	RepoPath       string `json:"repo_path"`
	Source         string `json:"source"` // "remote" or "local"
	Language       string `json:"language"`
	CommitSHA      string `json:"commit_sha"`
	CommitSHAShort string `json:"commit_sha_short"`
	CreatedAt      string `json:"created_at"`
}

// LoadProject reads the project.json for the named project.
func LoadProject(name string) (*Project, error) {
	projDir, err := ProjectDir(name)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(projDir, "project.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("project %q not found (no project.json at %s)", name, path)
		}
		return nil, fmt.Errorf("failed to read project: %w", err)
	}

	var p Project
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse project.json: %w", err)
	}

	return &p, nil
}

// SaveProject writes project.json to the project directory.
func SaveProject(p *Project) error {
	projDir, err := ProjectDir(p.Name)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(projDir, 0755); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize project: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(projDir, "project.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write project.json: %w", err)
	}

	return nil
}

// ActiveProject loads the currently active project.
func ActiveProject() (*Project, error) {
	cfg, err := Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ActiveProject == "" {
		return nil, fmt.Errorf("no active project. Run: openant init <repo-url-or-path> -l <language>")
	}

	return LoadProject(cfg.ActiveProject)
}

// SetActiveProject updates the global config with the active project name.
func SetActiveProject(name string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	cfg.ActiveProject = name
	return Save(cfg)
}

// ListProjects returns the names of all initialized projects.
// It walks ~/.openant/projects/ looking for project.json files.
func ListProjects() ([]string, error) {
	projsDir, err := ProjectsDir()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(projsDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	var names []string
	err = filepath.WalkDir(projsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if d.Name() == "project.json" && !d.IsDir() {
			// Extract project name from path:
			// ~/.openant/projects/org/repo/project.json → org/repo
			rel, err := filepath.Rel(projsDir, filepath.Dir(path))
			if err == nil {
				names = append(names, rel)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	return names, nil
}

// ShortSHA returns the first 11 characters of a SHA.
func ShortSHA(sha string) string {
	if len(sha) > 11 {
		return sha[:11]
	}
	return sha
}

// NewProject creates a Project with timestamps set.
func NewProject(name, repoURL, repoPath, source, language, commitSHA string) *Project {
	return &Project{
		Name:           name,
		RepoURL:        repoURL,
		RepoPath:       repoPath,
		Source:         source,
		Language:       language,
		CommitSHA:      commitSHA,
		CommitSHAShort: ShortSHA(commitSHA),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

// DeriveProjectName extracts "org/repo" from a URL or local path.
//
// Examples:
//
//	https://github.com/grafana/grafana       → grafana/grafana
//	https://github.com/grafana/grafana.git   → grafana/grafana
//	git@github.com:org/repo.git              → org/repo
//	./repos/grafana                           → grafana
//	/absolute/path/to/myproject              → myproject
func DeriveProjectName(input string) string {
	// Try SSH format: git@github.com:org/repo.git
	if strings.Contains(input, ":") && strings.Contains(input, "@") {
		parts := strings.SplitN(input, ":", 2)
		if len(parts) == 2 {
			name := parts[1]
			name = strings.TrimSuffix(name, ".git")
			return name
		}
	}

	// Try HTTP(S) URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		u, err := url.Parse(input)
		if err == nil {
			path := strings.TrimPrefix(u.Path, "/")
			path = strings.TrimSuffix(path, ".git")
			// path is "org/repo" or "org/repo/..."
			parts := strings.SplitN(path, "/", 3)
			if len(parts) >= 2 {
				return parts[0] + "/" + parts[1]
			}
			if len(parts) == 1 && parts[0] != "" {
				return parts[0]
			}
		}
	}

	// Local path — use the last directory component
	abs, err := filepath.Abs(input)
	if err != nil {
		return filepath.Base(input)
	}
	return filepath.Base(abs)
}

// IsURL returns true if the input looks like a git URL.
func IsURL(input string) bool {
	return strings.HasPrefix(input, "http://") ||
		strings.HasPrefix(input, "https://") ||
		strings.HasPrefix(input, "git@") ||
		strings.HasPrefix(input, "ssh://")
}
