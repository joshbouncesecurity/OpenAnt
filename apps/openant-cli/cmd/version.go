package cmd

import (
	"runtime"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	pythonVersion := ""
	rt, err := python.DetectRuntime()
	if err == nil {
		pythonVersion = rt.Version
	}

	output.PrintVersion(version, runtime.Version(), pythonVersion)
}
