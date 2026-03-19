package cmd

import (
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [results-path]",
	Short: "Run Stage 2 verification on analysis results",
	Long: `Verify runs Stage 2 attacker simulation on Stage 1 analysis results.

Only findings classified as vulnerable or bypassable are verified.
The model role-plays as an attacker with only a browser, attempting
to exploit each vulnerability step-by-step. This eliminates false
positives by surfacing roadblocks that make theoretical vulnerabilities
unexploitable.

If no results path is given, the active project's results.json is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runVerify,
}

var (
	verifyOutput         string
	verifyAnalyzerOutput string
	verifyAppContext     string
	verifyRepoPath       string
	verifyFresh          bool
)

func init() {
	verifyCmd.Flags().StringVarP(&verifyOutput, "output", "o", "", "Output directory")
	verifyCmd.Flags().StringVar(&verifyAnalyzerOutput, "analyzer-output", "", "Path to analyzer_output.json")
	verifyCmd.Flags().StringVar(&verifyAppContext, "app-context", "", "Path to application_context.json")
	verifyCmd.Flags().StringVar(&verifyRepoPath, "repo-path", "", "Path to the repository")
	verifyCmd.Flags().BoolVar(&verifyFresh, "fresh", false, "Ignore checkpoint and reverify all findings from scratch")
}

func runVerify(cmd *cobra.Command, args []string) {
	resultsPath, ctx, err := resolveFileArg(args, "results.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if verifyOutput == "" {
			verifyOutput = ctx.ScanDir
		}
		if verifyAnalyzerOutput == "" {
			verifyAnalyzerOutput = ctx.scanFile("analyzer_output.json")
		}
		if verifyRepoPath == "" {
			verifyRepoPath = ctx.RepoPath
		}
	}
	if verifyAnalyzerOutput == "" {
		output.PrintError("--analyzer-output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := []string{"verify", resultsPath, "--analyzer-output", verifyAnalyzerOutput}
	if verifyOutput != "" {
		pyArgs = append(pyArgs, "--output", verifyOutput)
	}
	if verifyAppContext != "" {
		pyArgs = append(pyArgs, "--app-context", verifyAppContext)
	}
	if verifyRepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", verifyRepoPath)
	}
	if verifyFresh {
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
			output.PrintVerifySummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
