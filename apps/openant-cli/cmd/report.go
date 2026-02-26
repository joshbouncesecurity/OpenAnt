package cmd

import (
	"os"
	"path/filepath"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [results-path]",
	Short: "Generate reports from analysis results",
	Long: `Report generates reports from analysis results or pipeline output.

Formats:
  html         HTML report with interactive findings (default)
  csv          CSV export of all findings
  summary      Markdown summary report (requires --pipeline-output)
  disclosure   Per-vulnerability disclosure documents (requires --pipeline-output)

If no results path is given, the active project's results_verified.json is used.

Examples:
  openant report results.json -o report/ --dataset dataset.json
  openant report --pipeline-output pipeline_output.json -f summary -o report/SUMMARY.md
  openant report -f disclosure -o report/disclosures/`,
	Args: cobra.MaximumNArgs(1),
	Run:  runReport,
}

var (
	reportOutput         string
	reportDataset        string
	reportFormat         string
	reportPipelineOutput string
	reportRepoName       string
)

func init() {
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output path")
	reportCmd.Flags().StringVar(&reportDataset, "dataset", "", "Path to dataset JSON (for html/csv)")
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "html", "Report format: html, csv, summary, disclosure")
	reportCmd.Flags().StringVar(&reportPipelineOutput, "pipeline-output", "", "Path to pipeline_output.json (for summary/disclosure)")
	reportCmd.Flags().StringVar(&reportRepoName, "repo-name", "", "Repository name (used when auto-building pipeline_output)")
}

func runReport(cmd *cobra.Command, args []string) {
	resultsPath, ctx, err := resolveFileArg(args, "results_verified.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if reportOutput == "" {
			reportOutput = filepath.Join(ctx.ScanDir, "report")
		}
		if reportPipelineOutput == "" {
			reportPipelineOutput = ctx.scanFile("pipeline_output.json")
		}
		if reportRepoName == "" {
			reportRepoName = ctx.Project.Name
		}
		if reportDataset == "" {
			reportDataset = ctx.scanFile("dataset_enhanced.json")
		}
	}
	if reportOutput == "" {
		output.PrintError("--output is required (or use openant init to set up a project)")
		os.Exit(2)
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pyArgs := []string{"report", resultsPath, "--output", reportOutput}
	if reportFormat != "html" {
		pyArgs = append(pyArgs, "--format", reportFormat)
	}
	if reportDataset != "" {
		pyArgs = append(pyArgs, "--dataset", reportDataset)
	}
	if reportPipelineOutput != "" {
		pyArgs = append(pyArgs, "--pipeline-output", reportPipelineOutput)
	}
	if reportRepoName != "" {
		pyArgs = append(pyArgs, "--repo-name", reportRepoName)
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, resolvedAPIKey())
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintReportSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
