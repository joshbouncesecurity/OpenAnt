package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var generateContextCmd = &cobra.Command{
	Use:   "generate-context [repository-path]",
	Short: "Generate application security context for a repository",
	Long: `Generate analyzes a repository and produces an application_context.json
file that describes the application type, trust boundaries, intended
behaviors, and patterns that should not be flagged as vulnerabilities.

This context is automatically used by the analyze and verify commands
to reduce false positives.

If no repository path is given, the active project is used (see: openant init).

The command checks for a manual override file (OPENANT.md or OPENANT.json)
in the repository root before falling back to LLM-based generation.

When an override file is found, you are prompted to choose how to handle it:
  use    - Use the override file as-is (skip LLM generation)
  merge  - Feed the override file into the LLM alongside other sources
  ignore - Ignore the override and generate from scratch

Use --override-mode to skip the prompt, or --force as a shortcut for --override-mode=ignore.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runGenerateContext,
}

var (
	gcOutput       string
	gcForce        bool
	gcOverrideMode string
	gcShowPrompt   bool
)

// overrideFiles lists manual override filenames checked in the target repo.
var overrideFiles = []string{"OPENANT.md", "OPENANT.json", ".openant.md", ".openant.json"}

func init() {
	generateContextCmd.Flags().StringVarP(&gcOutput, "output", "o", "", "Output path (default: <scan-dir>/application_context.json or <repo>/application_context.json)")
	generateContextCmd.Flags().BoolVar(&gcForce, "force", false, "Force regeneration, ignoring OPENANT.md override files")
	generateContextCmd.Flags().StringVar(&gcOverrideMode, "override-mode", "", "How to handle OPENANT.md: use, merge, or ignore (skips interactive prompt)")
	generateContextCmd.Flags().BoolVar(&gcShowPrompt, "show-prompt", false, "Include formatted prompt text in output")
}

func runGenerateContext(cmd *cobra.Command, args []string) {
	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if gcOutput == "" {
			gcOutput = ctx.scanFile("application_context.json")
		}
	}

	// Resolve effective override mode
	effectiveMode, err := resolveOverrideMode(repoPath)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Build Python CLI args
	pyArgs := []string{"generate-context", repoPath}
	if gcOutput != "" {
		pyArgs = append(pyArgs, "--output", gcOutput)
	}
	if effectiveMode != "" {
		pyArgs = append(pyArgs, "--override-mode", effectiveMode)
	}
	if gcShowPrompt {
		pyArgs = append(pyArgs, "--show-prompt")
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey())
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			printGenerateContextSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}

// resolveOverrideMode determines the effective override mode based on flags
// and interactive prompting.
func resolveOverrideMode(repoPath string) (string, error) {
	// --force and --override-mode are mutually exclusive
	if gcForce && gcOverrideMode != "" {
		return "", fmt.Errorf("--force and --override-mode are mutually exclusive")
	}

	// --force is a shortcut for --override-mode=ignore
	if gcForce {
		return "ignore", nil
	}

	// Explicit --override-mode takes precedence
	if gcOverrideMode != "" {
		mode := strings.ToLower(gcOverrideMode)
		if mode != "use" && mode != "merge" && mode != "ignore" {
			return "", fmt.Errorf("invalid --override-mode %q: must be use, merge, or ignore", gcOverrideMode)
		}
		return mode, nil
	}

	// No explicit flag — check for override file
	overrideFile := findOverrideFile(repoPath)
	if overrideFile == "" {
		// No override file exists; let Python use default LLM generation
		return "", nil
	}

	// Override file found — prompt if interactive, else default to "use"
	if !isInteractiveTerminal() {
		return "use", nil
	}

	return promptOverrideMode(overrideFile), nil
}

// findOverrideFile checks for manual override files in the repo root.
// Returns the filename if found, empty string otherwise.
func findOverrideFile(repoPath string) string {
	for _, name := range overrideFiles {
		path := filepath.Join(repoPath, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return name
		}
	}
	return ""
}

// isInteractiveTerminal returns true if stdin is a terminal (not piped/CI).
func isInteractiveTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// promptOverrideMode shows an interactive prompt for how to handle the override file.
func promptOverrideMode(filename string) string {
	fmt.Fprintf(os.Stderr, "\nFound manual override: %s\n\n", filename)
	fmt.Fprintln(os.Stderr, "  [u]se    — Use as-is (skip LLM generation)")
	fmt.Fprintln(os.Stderr, "  [m]erge  — Feed into LLM alongside other sources")
	fmt.Fprintln(os.Stderr, "  [i]gnore — Ignore, generate from scratch")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprint(os.Stderr, "Choice [u/m/i] (default: u): ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	switch answer {
	case "m", "merge":
		return "merge"
	case "i", "ignore":
		return "ignore"
	default:
		// "u", "use", or empty (default)
		return "use"
	}
}

func printGenerateContextSummary(data map[string]any) {
	output.PrintHeader("Application Context Generated")
	if v, ok := data["application_type"].(string); ok {
		output.PrintKeyValue("Type", v)
	}
	if v, ok := data["purpose"].(string); ok {
		output.PrintKeyValue("Purpose", v)
	}
	if v, ok := data["confidence"].(float64); ok {
		output.PrintKeyValue("Confidence", fmt.Sprintf("%.0f%%", v*100))
	}
	if v, ok := data["source"].(string); ok {
		output.PrintKeyValue("Source", v)
	}
	if v, ok := data["app_context_path"].(string); ok {
		output.PrintKeyValue("Output", v)
	}
	fmt.Println()
}
