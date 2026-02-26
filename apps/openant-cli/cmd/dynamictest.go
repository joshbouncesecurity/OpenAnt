package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var dynamicTestCmd = &cobra.Command{
	Use:   "dynamic-test [pipeline-output-path]",
	Short: "Run Docker-isolated dynamic exploit testing",
	Long: `Dynamic-test runs confirmed vulnerabilities through Docker-isolated
exploit testing. Each finding gets its own container where the exploit
is attempted in a real environment.

Requires Docker to be installed and running.
Requires pipeline_output.json from the build-output or scan command.

If no path is given, the active project's pipeline_output.json is used.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDynamicTest,
}

var (
	dynamicTestOutput     string
	dynamicTestMaxRetries int
)

func init() {
	dynamicTestCmd.Flags().StringVarP(&dynamicTestOutput, "output", "o", "", "Output directory")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxRetries, "max-retries", 3, "Max retries per finding on error")
}

func runDynamicTest(cmd *cobra.Command, args []string) {
	pipelineOutputPath, ctx, err := resolveFileArg(args, "pipeline_output.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if dynamicTestOutput == "" {
			dynamicTestOutput = ctx.ScanDir
		}
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := []string{"dynamic-test", pipelineOutputPath}
	if dynamicTestOutput != "" {
		pyArgs = append(pyArgs, "--output", dynamicTestOutput)
	}
	if dynamicTestMaxRetries != 3 {
		pyArgs = append(pyArgs, "--max-retries", fmt.Sprintf("%d", dynamicTestMaxRetries))
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
			output.PrintDynamicTestSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
