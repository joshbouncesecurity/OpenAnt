package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/knostic/open-ant-cli/internal/config"
)

// projectContext holds resolved paths from the active project.
type projectContext struct {
	Project  *config.Project
	ScanDir  string // ~/.openant/projects/org/repo/scans/{sha}/
	RepoPath string
	Language string
}

// resolveProject loads the project to use and returns a context with
// all commonly-needed paths pre-resolved.
//
// Resolution order: --project flag > active_project in config.
func resolveProject() (*projectContext, error) {
	var project *config.Project
	var err error

	if projectFlag != "" {
		project, err = config.LoadProject(projectFlag)
		if err != nil {
			return nil, fmt.Errorf("--project %s: %w", projectFlag, err)
		}
	} else {
		project, err = config.ActiveProject()
		if err != nil {
			return nil, err
		}
	}

	scanDir, err := config.ScanDir(project.Name, project.CommitSHAShort, project.Language)
	if err != nil {
		return nil, err
	}

	return &projectContext{
		Project:  project,
		ScanDir:  scanDir,
		RepoPath: project.RepoPath,
		Language: project.Language,
	}, nil
}

// scanFile returns the full path to a file in the active scan directory.
func (ctx *projectContext) scanFile(name string) string {
	return filepath.Join(ctx.ScanDir, name)
}

// resolveRepoArg returns the repo path: from the positional arg if provided,
// or from the active project.
func resolveRepoArg(args []string) (string, *projectContext, error) {
	if len(args) > 0 && args[0] != "" {
		return args[0], nil, nil
	}

	ctx, err := resolveProject()
	if err != nil {
		return "", nil, fmt.Errorf("no repository specified and %w", err)
	}
	return ctx.RepoPath, ctx, nil
}

// resolveFileArg returns a file path: from the positional arg if provided,
// or constructed from the active project's scan dir.
func resolveFileArg(args []string, defaultFilename string) (string, *projectContext, error) {
	if len(args) > 0 && args[0] != "" {
		return args[0], nil, nil
	}

	ctx, err := resolveProject()
	if err != nil {
		return "", nil, fmt.Errorf("no file specified and %w", err)
	}
	return ctx.scanFile(defaultFilename), ctx, nil
}
