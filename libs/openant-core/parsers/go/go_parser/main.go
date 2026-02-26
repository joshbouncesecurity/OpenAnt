package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "extract":
		cmdExtract(os.Args[2:])
	case "callgraph":
		cmdCallGraph(os.Args[2:])
	case "generate":
		cmdGenerate(os.Args[2:])
	case "all":
		cmdAll(os.Args[2:])
	case "version":
		fmt.Printf("go_parser version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`go_parser - Go static parser for OpenAnt

Usage:
  go_parser <command> [options] <repository_path>

Commands:
  scan       Stage 1: Scan repository for Go files
  extract    Stage 2: Extract functions and methods
  callgraph  Stage 3: Build call graphs
  generate   Stage 4: Generate OpenAnt dataset
  all        Run all stages (scan -> extract -> callgraph -> generate)
  version    Print version
  help       Print this help

Options:
  --output, -o    Output file path (default: stdout)
  --skip-tests    Skip test files (*_test.go)
  --depth         Dependency resolution depth (default: 3)

Examples:
  go_parser scan --output scan_results.json /path/to/repo
  go_parser extract --output analyzer_output.json /path/to/repo
  go_parser callgraph --output call_graph.json /path/to/repo
  go_parser generate --output dataset.json /path/to/repo
  go_parser all --output dataset.json /path/to/repo

Note: Flags must come BEFORE the repository path.`)
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Output file path")
	fs.StringVar(&outputPath, "o", "", "Output file path (short)")
	skipTests := fs.Bool("skip-tests", false, "Skip test files")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: repository path required")
		os.Exit(1)
	}

	repoPath, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(1)
	}

	scanner := NewScanner(repoPath, *skipTests)
	result, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	writeJSON(result, outputPath)
	fmt.Fprintf(os.Stderr, "Scanned %d Go files\n", result.Statistics.TotalFiles)
}

func cmdExtract(args []string) {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Output file path")
	fs.StringVar(&outputPath, "o", "", "Output file path (short)")
	skipTests := fs.Bool("skip-tests", false, "Skip test files")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: repository path required")
		os.Exit(1)
	}

	repoPath, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(1)
	}

	// First scan for files
	scanner := NewScanner(repoPath, *skipTests)
	scanResult, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	// Extract functions
	extractor := NewExtractor(repoPath)
	filePaths := scanner.GetFilePaths(scanResult)
	result, err := extractor.Extract(filePaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
		os.Exit(1)
	}

	writeJSON(result, outputPath)
	fmt.Fprintf(os.Stderr, "Extracted %d functions from %d files\n", len(result.Functions), scanResult.Statistics.TotalFiles)
}

func cmdCallGraph(args []string) {
	fs := flag.NewFlagSet("callgraph", flag.ExitOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Output file path")
	fs.StringVar(&outputPath, "o", "", "Output file path (short)")
	skipTests := fs.Bool("skip-tests", false, "Skip test files")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: repository path required")
		os.Exit(1)
	}

	repoPath, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(1)
	}

	// First scan and extract
	scanner := NewScanner(repoPath, *skipTests)
	scanResult, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	extractor := NewExtractor(repoPath)
	filePaths := scanner.GetFilePaths(scanResult)
	analyzer, err := extractor.Extract(filePaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
		os.Exit(1)
	}

	// Build call graph
	builder := NewCallGraphBuilder(repoPath)
	result, err := builder.BuildCallGraph(analyzer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building call graph: %v\n", err)
		os.Exit(1)
	}

	writeJSON(result, outputPath)
	fmt.Fprintf(os.Stderr, "Built call graph: %d nodes, %d edges\n", result.Statistics.TotalNodes, result.Statistics.TotalEdges)
}

func cmdGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Output file path")
	fs.StringVar(&outputPath, "o", "", "Output file path (short)")
	skipTests := fs.Bool("skip-tests", false, "Skip test files")
	depth := fs.Int("depth", 3, "Dependency resolution depth")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: repository path required")
		os.Exit(1)
	}

	repoPath, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(1)
	}

	// Run full pipeline
	dataset, err := runFullPipeline(repoPath, *skipTests, *depth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	writeJSON(dataset, outputPath)
	fmt.Fprintf(os.Stderr, "Generated dataset: %d units\n", dataset.Statistics.TotalUnits)
}

func cmdAll(args []string) {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "Output file path for dataset")
	fs.StringVar(&outputPath, "o", "", "Output file path (short)")
	skipTests := fs.Bool("skip-tests", false, "Skip test files")
	depth := fs.Int("depth", 3, "Dependency resolution depth")
	analyzerOutput := fs.String("analyzer-output", "", "Also output analyzer_output.json")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: repository path required")
		os.Exit(1)
	}

	repoPath, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(1)
	}

	// Stage 1: Scan
	fmt.Fprintln(os.Stderr, "Stage 1: Scanning repository...")
	scanner := NewScanner(repoPath, *skipTests)
	scanResult, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Found %d Go files\n", scanResult.Statistics.TotalFiles)

	// Stage 2: Extract
	fmt.Fprintln(os.Stderr, "Stage 2: Extracting functions...")
	extractor := NewExtractor(repoPath)
	filePaths := scanner.GetFilePaths(scanResult)
	analyzer, err := extractor.Extract(filePaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Extracted %d functions\n", len(analyzer.Functions))

	// Optionally write analyzer output
	if *analyzerOutput != "" {
		writeJSON(analyzer, *analyzerOutput)
		fmt.Fprintf(os.Stderr, "  Wrote analyzer output to %s\n", *analyzerOutput)
	}

	// Stage 3: Call graph
	fmt.Fprintln(os.Stderr, "Stage 3: Building call graph...")
	builder := NewCallGraphBuilder(repoPath)
	callGraph, err := builder.BuildCallGraph(analyzer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building call graph: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Built call graph: %d edges\n", callGraph.Statistics.TotalEdges)

	// Stage 4: Generate
	fmt.Fprintln(os.Stderr, "Stage 4: Generating dataset...")
	generator := NewGenerator(repoPath, analyzer, callGraph, *depth)
	dataset := generator.Generate()
	fmt.Fprintf(os.Stderr, "  Generated %d units\n", dataset.Statistics.TotalUnits)

	writeJSON(dataset, outputPath)
	fmt.Fprintln(os.Stderr, "Done!")
}

func runFullPipeline(repoPath string, skipTests bool, depth int) (*Dataset, error) {
	// Stage 1: Scan
	scanner := NewScanner(repoPath, skipTests)
	scanResult, err := scanner.Scan()
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Stage 2: Extract
	extractor := NewExtractor(repoPath)
	filePaths := scanner.GetFilePaths(scanResult)
	analyzer, err := extractor.Extract(filePaths)
	if err != nil {
		return nil, fmt.Errorf("extract failed: %w", err)
	}

	// Stage 3: Call graph
	builder := NewCallGraphBuilder(repoPath)
	callGraph, err := builder.BuildCallGraph(analyzer)
	if err != nil {
		return nil, fmt.Errorf("call graph failed: %w", err)
	}

	// Stage 4: Generate
	generator := NewGenerator(repoPath, analyzer, callGraph, depth)
	return generator.Generate(), nil
}

func writeJSON(data interface{}, outputPath string) {
	var out *os.File
	var err error

	if outputPath == "" {
		out = os.Stdout
	} else {
		out, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
