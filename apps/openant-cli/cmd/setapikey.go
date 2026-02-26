package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key <key>",
	Short: "Save your Anthropic API key",
	Long: `Save your Anthropic API key to the OpenAnt config file.

The key is stored in ~/.config/openant/config.json with restricted
permissions (0600). This is required before running enhance, analyze,
verify, or scan.

Get an API key at https://console.anthropic.com/settings/keys

Examples:
  openant set-api-key sk-ant-api03-...`,
	Args: cobra.ExactArgs(1),
	Run:  runSetAPIKey,
}

func runSetAPIKey(cmd *cobra.Command, args []string) {
	key := strings.TrimSpace(args[0])
	if key == "" {
		output.PrintError("API key cannot be empty")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	cfg.APIKey = key

	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n")
	output.PrintSuccess(fmt.Sprintf("API key saved (%s)", config.MaskKey(key)))
	fmt.Fprintf(os.Stderr, "\n")
}
