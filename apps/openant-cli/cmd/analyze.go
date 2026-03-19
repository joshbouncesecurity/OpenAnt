package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [dataset-path]",
	Short: "Run vulnerability analysis on parsed data",
	Long: `Analyze runs Claude-powered Stage 1 vulnerability detection on a parsed dataset.

With --verify, it chains into Stage 2 attacker simulation automatically.
For standalone Stage 2, use the verify command instead.

If no dataset path is given, the active project's enhanced dataset is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runAnalyze,
}

var (
	analyzeOutput         string
	analyzeVerify         bool
	analyzeAnalyzerOutput string
	analyzeAppContext     string
	analyzeRepoPath       string
	analyzeExploitOnly    bool
	analyzeLimit          int
	analyzeModel          string
	analyzeFresh          bool
)

func init() {
	analyzeCmd.Flags().StringVarP(&analyzeOutput, "output", "o", "", "Output directory")
	analyzeCmd.Flags().BoolVar(&analyzeVerify, "verify", false, "Chain into Stage 2 attacker simulation after detection")
	analyzeCmd.Flags().StringVar(&analyzeAnalyzerOutput, "analyzer-output", "", "Path to analyzer_output.json (for Stage 2)")
	analyzeCmd.Flags().StringVar(&analyzeAppContext, "app-context", "", "Path to application_context.json")
	analyzeCmd.Flags().StringVar(&analyzeRepoPath, "repo-path", "", "Path to the repository (for context correction)")
	analyzeCmd.Flags().BoolVar(&analyzeExploitOnly, "exploitable-only", false, "Only analyze units classified as exploitable by enhancer")
	analyzeCmd.Flags().IntVar(&analyzeLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	analyzeCmd.Flags().StringVar(&analyzeModel, "model", "opus", "Model: opus or sonnet")
	analyzeCmd.Flags().BoolVar(&analyzeFresh, "fresh", false, "Ignore checkpoint and reanalyze all units from scratch")
}

func runAnalyze(cmd *cobra.Command, args []string) {
	datasetPath, ctx, err := resolveFileArg(args, "dataset_enhanced.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if analyzeOutput == "" {
			analyzeOutput = ctx.ScanDir
		}
		if analyzeAnalyzerOutput == "" {
			analyzeAnalyzerOutput = ctx.scanFile("analyzer_output.json")
		}
		if analyzeRepoPath == "" {
			analyzeRepoPath = ctx.RepoPath
		}
	}
	if analyzeOutput == "" {
		output.PrintError("--output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := []string{"analyze", datasetPath, "--output", analyzeOutput}
	if analyzeVerify {
		pyArgs = append(pyArgs, "--verify")
	}
	if analyzeAnalyzerOutput != "" {
		pyArgs = append(pyArgs, "--analyzer-output", analyzeAnalyzerOutput)
	}
	if analyzeAppContext != "" {
		pyArgs = append(pyArgs, "--app-context", analyzeAppContext)
	}
	if analyzeRepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", analyzeRepoPath)
	}
	if analyzeExploitOnly {
		pyArgs = append(pyArgs, "--exploitable-only")
	}
	if analyzeLimit > 0 {
		pyArgs = append(pyArgs, "--limit", fmt.Sprintf("%d", analyzeLimit))
	}
	if analyzeModel != "opus" {
		pyArgs = append(pyArgs, "--model", analyzeModel)
	}
	if analyzeFresh {
		pyArgs = append(pyArgs, "--fresh")
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
			output.PrintAnalyzeSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
