// OpenAnt CLI - LLM-powered static analysis security testing.
//
// This binary wraps the Python `open_ant` package, providing a native CLI
// experience with colored output, progress streaming, and JSON mode.
package main

import "github.com/knostic/open-ant-cli/cmd"

func main() {
	cmd.Execute()
}
