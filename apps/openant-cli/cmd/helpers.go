package cmd

import (
	"github.com/knostic/open-ant-cli/internal/python"
)

// ensurePython detects the Python runtime and validates that openant is installed.
// If needed, creates a managed venv at ~/.openant/venv/ and installs the package.
func ensurePython() (*python.RuntimeInfo, error) {
	return python.EnsureRuntime()
}
