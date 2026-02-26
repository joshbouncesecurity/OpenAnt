// Package python provides subprocess invocation of the Python CLI.
package python

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/knostic/open-ant-cli/internal/types"
)

// InvokeResult holds the result of a Python CLI invocation.
type InvokeResult struct {
	Envelope types.Envelope
	ExitCode int
}

// Invoke runs `python -m openant <args>` and returns the parsed JSON result.
//
// - stderr is streamed to the terminal in real-time (progress messages)
// - stdout is captured and parsed as JSON
// - Working directory is set to the openant-core lib directory if provided
// - If apiKey is non-empty, it is injected as ANTHROPIC_API_KEY in the subprocess
func Invoke(pythonPath string, args []string, workDir string, quiet bool, apiKey string) (*InvokeResult, error) {
	cmdArgs := append([]string{"-m", "openant"}, args...)
	cmd := exec.Command(pythonPath, cmdArgs...)

	if workDir != "" {
		cmd.Dir = workDir
	}

	// Pass through environment (Python needs ANTHROPIC_API_KEY, etc.)
	// If an API key is provided via flag or config, inject it into the
	// subprocess environment so Python picks it up regardless of .env files.
	cmd.Env = os.Environ()
	if apiKey != "" {
		cmd.Env = setEnv(cmd.Env, "ANTHROPIC_API_KEY", apiKey)
	}

	// Capture stdout (JSON output)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Stream stderr to terminal (progress messages)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Python process: %w", err)
	}

	// Stream stderr in a goroutine
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		streamStderr(stderr, quiet)
	}()

	// Read all stdout
	var stdoutBuf strings.Builder
	if _, err := io.Copy(&stdoutBuf, stdout); err != nil {
		return nil, fmt.Errorf("failed to read stdout: %w", err)
	}

	// Wait for stderr streaming to finish
	<-stderrDone

	// Wait for process to exit
	exitErr := cmd.Wait()
	exitCode := 0
	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("failed waiting for Python process: %w", exitErr)
		}
	}

	// Parse JSON from stdout
	rawJSON := strings.TrimSpace(stdoutBuf.String())
	if rawJSON == "" {
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{"Python process produced no output on stdout"},
			},
			ExitCode: exitCode,
		}, nil
	}

	var envelope types.Envelope
	if err := json.Unmarshal([]byte(rawJSON), &envelope); err != nil {
		return &InvokeResult{
			Envelope: types.Envelope{
				Status: "error",
				Errors: []string{
					fmt.Sprintf("Failed to parse JSON output: %s", err),
					fmt.Sprintf("Raw output: %s", truncate(rawJSON, 500)),
				},
			},
			ExitCode: exitCode,
		}, nil
	}

	return &InvokeResult{
		Envelope: envelope,
		ExitCode: exitCode,
	}, nil
}

// streamStderr reads stderr line by line and writes to os.Stderr.
// If quiet is true, stderr output is suppressed.
func streamStderr(r io.Reader, quiet bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if !quiet {
			fmt.Fprintln(os.Stderr, scanner.Text())
		}
	}
}

// setEnv sets or replaces an environment variable in a []string env slice.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// truncate shortens a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
