# Go Parser Pipeline

**Last Updated**: 2026-01-12 (Initial Implementation)

---

## Overview

The OpenAnt Go parser pipeline transforms Go repositories into structured datasets for security analysis. It uses a native Go binary for fast AST parsing and a Python orchestrator for filtering and LLM integration.

---

## Processing Levels

The pipeline supports four processing levels with cumulative filtering:

| Level | Name | Filter | Stages | Cost |
|-------|------|--------|--------|------|
| 1 | `all` | None | 1-4 | Highest |
| 2 | `reachable` | Entry point reachability | 1-4 + 3.5 | Moderate |
| 3 | `codeql` | Reachable + CodeQL-flagged | 1-4 + 3.5 + 3.6-3.7 | Low |
| 4 | `exploitable` | Reachable + CodeQL + Exploitable | 1-4 + 3.5 + 3.6-3.7 + 4 + 4.5 | Lowest |

**Example cost savings (object-browser):**

| Level | Units | Reduction |
|-------|-------|-----------|
| All | 1,260 | - |
| Reachable | 92 | 92.7% |
| CodeQL | TBD | TBD |
| Exploitable | TBD | TBD |

**What each level excludes:**

| Level | Code NOT Processed |
|-------|-------------------|
| 1: all | None - complete coverage |
| 2: reachable | Internal utilities, dead code, non-entry-point reachable functions |
| 3: codeql | Reachable code without known vulnerability patterns (SQLi, command injection, etc.) |
| 4: exploitable | CodeQL-flagged code classified as security_control, neutral, or vulnerable_internal |

---

## Architecture

The Go parser uses a hybrid architecture:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         GO BINARY (go_parser)                            │
│                   Fast native AST parsing using go/ast                   │
├─────────────────────────────────────────────────────────────────────────┤
│  Subcommand: scan      → Stage 1: File discovery                        │
│  Subcommand: extract   → Stage 2: Function extraction                   │
│  Subcommand: callgraph → Stage 3: Call graph building                   │
│  Subcommand: generate  → Stage 4: Dataset generation                    │
│  Subcommand: all       → Run all stages in sequence                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    PYTHON ORCHESTRATOR (test_pipeline.py)                │
│              Filtering, CodeQL integration, LLM enhancement              │
├─────────────────────────────────────────────────────────────────────────┤
│  Stage 3.5: Reachability Filter                                         │
│  Stage 3.6: CodeQL Analysis                                             │
│  Stage 3.7: CodeQL Filter                                               │
│  Stage 4:   Context Enhancer (LLM)                                      │
│  Stage 4.5: Exploitable Filter                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Stages

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           GO STAGES (1-4)                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 1: Scanner                                                        │
│  ───────────────                                                         │
│  Input:  Repository path                                                 │
│  Output: List of all .go files                                           │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 2: Extractor                                                      │
│  ─────────────────                                                       │
│  Input:  File list from Stage 1                                          │
│  Output: analyzer_output.json (all functions with metadata)              │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3: CallGraphBuilder                                               │
│  ────────────────────────                                                │
│  Input:  Functions from Stage 2                                          │
│  Output: Bidirectional call graph (forward + reverse)                    │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 4: Generator                                                      │
│  ─────────────────                                                       │
│  Input:  Functions + call graph                                          │
│  Output: dataset.json (OpenAnt dataset format)                          │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                     FILTERING STAGES (3.5-3.7) - Optional                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 3.5: ReachabilityFilter (if --processing-level >= reachable)      │
│  ─────────────────────────────                                           │
│  Input:  dataset.json + analyzer_output.json                             │
│  Output: dataset.json (filtered to reachable units)                      │
│  Method: BFS from entry points via reverse call graph                    │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3.6: CodeQL Analysis (if --processing-level >= codeql)            │
│  ───────────────────────────                                             │
│  Input:  Repository path                                                 │
│  Output: codeql-results.sarif (vulnerability findings)                   │
│  Method: CodeQL database + go-security-extended queries                  │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 3.7: CodeQL Filter (if --processing-level >= codeql)              │
│  ─────────────────────────                                               │
│  Input:  dataset.json + SARIF results                                    │
│  Output: dataset.json (filtered to CodeQL-flagged units)                 │
│  Method: Map SARIF file:line to function units                           │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                     LLM ENHANCEMENT STAGES (4-4.5) - Optional            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 4: ContextEnhancer                                                │
│  ────────────────────────                                                │
│  Input:  dataset.json + analyzer_output.json                             │
│  Output: dataset.json (enhanced with LLM context)                        │
│  Modes:  Single-shot (fast) or Agentic (accurate)                        │
│  Model:  Claude Sonnet                                                   │
│                                                                          │
│                              ↓                                           │
│                                                                          │
│  Stage 4.5: ExploitableFilter (if --processing-level == exploitable)     │
│  ────────────────────────────                                            │
│  Input:  dataset.json (with agent_context.security_classification)       │
│  Output: dataset.json (filtered to exploitable units only)               │
│  Method: Keep only units classified as "exploitable"                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Build the Go Parser

```bash
cd parsers/go/go_parser
go build -o go_parser .
```

### Processing Levels

```bash
# Level 1: All units (no filtering)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level all

# Level 2: Reachable units only (~93% cost reduction)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level reachable

# Level 3: Reachable + CodeQL-flagged (~99% cost reduction)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level codeql

# Level 4: Exploitable only (maximum cost savings)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --processing-level exploitable \
    --llm --agentic
```

### With LLM Enhancement

```bash
# Single-shot LLM enhancement (fast, less accurate)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --llm

# Agentic LLM enhancement (recommended for Level 4)
python3 test_pipeline.py /path/to/go/repo \
    --output /path/to/output \
    --llm --agentic
```

### Run Go Parser Directly

```bash
# Run all stages at once (recommended)
./go_parser all --output dataset.json /path/to/repo

# Run individual stages
./go_parser scan --output scan.json /path/to/repo
./go_parser extract --output analyzer.json /path/to/repo
./go_parser callgraph --output callgraph.json /path/to/repo
./go_parser generate --output dataset.json /path/to/repo

# Skip test files
./go_parser all --output dataset.json --skip-tests /path/to/repo

# Also output analyzer_output.json (for filtering stages)
./go_parser all --output dataset.json --analyzer-output analyzer.json /path/to/repo
```

**Note**: Flags must come BEFORE the repository path.

---

## Stage 1: Scanner

**File**: `go_parser/scanner.go`

**Purpose**: Enumerate all Go source files in a repository.

**Input**:
- `repo_path`: Path to repository root

**Output** (embedded in pipeline):
```json
{
  "repository": "/path/to/repo",
  "files": [
    { "path": "api/handlers.go", "size": 5234, "extension": ".go" }
  ],
  "statistics": {
    "total_files": 189,
    "total_size_bytes": 500000
  }
}
```

**Behavior**:
- Recursively scans all directories
- Includes: `.go` files only
- Excludes: `vendor/`, `testdata/`, `.git/`, `node_modules/`, `_*` directories

---

## Stage 2: Extractor

**File**: `go_parser/extractor.go`

**Purpose**: Extract all functions and methods from Go source files using `go/ast`.

**Input**:
- File list from Stage 1

**Output** (`analyzer_output.json`):
```json
{
  "repo_root": "/path/to/repo",
  "functions": {
    "api/handlers.go:HandleRequest": {
      "name": "HandleRequest",
      "code": "func HandleRequest(w http.ResponseWriter, r *http.Request) { ... }",
      "start_line": 15,
      "end_line": 45,
      "unit_type": "http_handler",
      "class_name": "",
      "is_exported": true,
      "package": "api",
      "receiver": "",
      "parameters": ["w http.ResponseWriter", "r *http.Request"],
      "returns": []
    }
  }
}
```

**Unit Types**:

| Type | Detection |
|------|-----------|
| `main` | Function named "main" in package "main" |
| `init` | Function named "init" |
| `test` | Function with `*testing.T` or `*testing.B` parameter |
| `http_handler` | Parameters include `http.ResponseWriter`, `*http.Request`, or framework types |
| `cli_handler` | Parameters include `*cobra.Command`, `*cli.Context`, or `*flag.FlagSet` |
| `middleware` | Returns `http.Handler` or calls `next()` |
| `method` | Function with a receiver |
| `function` | Default for standalone functions |

**HTTP Handler Detection Patterns**:
- `http.ResponseWriter`, `*http.Request`
- `gin.Context`, `echo.Context`, `fiber.Ctx`
- `chi.Router`, `mux.Router`
- `w.Write(`, `w.WriteHeader(`

**CLI Handler Detection Patterns**:
- `*cobra.Command`, `cli.Context`, `*flag.FlagSet`
- `os.Args`, `flag.Parse()`

---

## Stage 3: CallGraphBuilder

**File**: `go_parser/callgraph.go`

**Purpose**: Build bidirectional call graphs by analyzing function bodies.

**Input**:
- Functions from Stage 2

**Features**:
- Builds forward call graph (who does this function call)
- Builds reverse call graph (who calls this function)
- Resolves same-file functions
- Resolves same-package functions
- Resolves method calls on known types
- Filters out stdlib calls (`fmt`, `log`, `os`, etc.)

**Call Resolution Priority**:
1. Same file - exact name match
2. Same package (directory) - name match
3. Method on receiver type - type + method name match
4. Unique name match across repository

---

## Stage 4: Generator

**File**: `go_parser/generator.go`

**Purpose**: Create OpenAnt-compatible dataset from extracted functions and call graph.

**Output** (`dataset.json`):
```json
{
  "name": "repository-name",
  "repository": "/path/to/repo",
  "units": [
    {
      "id": "api/handlers.go:HandleRequest",
      "unit_type": "http_handler",
      "code": {
        "primary_code": "func HandleRequest(...) { ... }\n\n// ========== File Boundary ==========\n\nfunc helper() { ... }",
        "primary_origin": {
          "file_path": "api/handlers.go",
          "start_line": 15,
          "end_line": 45,
          "function_name": "HandleRequest",
          "class_name": "",
          "enhanced": true,
          "files_included": ["api/handlers.go", "api/helpers.go"],
          "original_length": 500,
          "enhanced_length": 1200
        },
        "dependencies": [],
        "dependency_metadata": {
          "depth": 3,
          "total_upstream": 5,
          "total_downstream": 2,
          "direct_calls": 3,
          "direct_callers": 1
        }
      },
      "ground_truth": {
        "status": "UNKNOWN",
        "vulnerability_types": [],
        "issues": []
      },
      "metadata": {
        "generator": "go_parser",
        "package": "api",
        "receiver": "",
        "is_exported": true,
        "parameters": ["w http.ResponseWriter", "r *http.Request"],
        "returns": [],
        "direct_calls": ["api/handlers.go:helper"],
        "direct_callers": ["main.go:main"]
      }
    }
  ],
  "statistics": {
    "total_units": 1260,
    "by_type": { "http_handler": 153, "method": 722, "function": 274 },
    "units_with_upstream": 50,
    "units_with_downstream": 30,
    "call_graph": {
      "total_nodes": 1260,
      "total_edges": 80,
      "avg_out_degree": 0.06,
      "max_out_degree": 25
    }
  },
  "metadata": {
    "generator": "go_parser",
    "generated_at": "2026-01-12T10:00:00Z",
    "dependency_depth": 3
  }
}
```

**Code Assembly**:

Dependencies are assembled into `primary_code` with file boundary markers:

```
primary function code

// ========== File Boundary ==========

dependency 1 code

// ========== File Boundary ==========

dependency 2 code
```

---

## Go-Specific Entry Points

The Go parser detects the following entry point patterns for reachability analysis:

| Pattern | Detection Method |
|---------|------------------|
| `main()` | Function named "main" in package "main" |
| `init()` | All functions named "init" |
| HTTP handlers | Signature includes `http.ResponseWriter` + `*http.Request` |
| Gin handlers | Parameter includes `*gin.Context` |
| Echo handlers | Parameter includes `echo.Context` |
| Fiber handlers | Parameter includes `*fiber.Ctx` |
| Chi/Mux routes | Route registration patterns |
| Cobra commands | `*cobra.Command` parameter or Run/RunE fields |
| CLI handlers | `*cli.Context` parameter |
| Test functions | `func Test*(t *testing.T)` |
| Benchmark functions | `func Benchmark*(b *testing.B)` |

---

## File Locations

| File | Location | Purpose |
|------|----------|---------|
| `go.mod` | `parsers/go/go_parser/` | Go module definition |
| `main.go` | `parsers/go/go_parser/` | CLI entry point |
| `types.go` | `parsers/go/go_parser/` | Shared data structures |
| `scanner.go` | `parsers/go/go_parser/` | Stage 1: File discovery |
| `extractor.go` | `parsers/go/go_parser/` | Stage 2: Function extraction |
| `callgraph.go` | `parsers/go/go_parser/` | Stage 3: Call graph building |
| `generator.go` | `parsers/go/go_parser/` | Stage 4: Dataset generation |
| `test_pipeline.py` | `parsers/go/` | Python orchestrator |
| `context_enhancer.py` | `utilities/` | LLM enhancement |
| `agentic_enhancer/` | `utilities/` | Agentic enhancement module |

---

## Dependencies

### Go
```bash
# Go 1.21+ required
# No external dependencies - uses only stdlib
cd parsers/go/go_parser
go build -o go_parser .
```

### Python
```bash
pip install anthropic python-dotenv
```

### CodeQL (for Level 3+)
```bash
# macOS
brew install codeql

# Download Go query pack
codeql pack download codeql/go-queries
```

---

## Troubleshooting

### "No files found" (Stage 1)
- Check repository path exists
- Verify .go files exist outside vendor/
- Check exclude patterns aren't matching your code

### "0 functions extracted" (Stage 2)
- Check for Go syntax errors in source files
- Try running `go build` in the repo first
- Verify files have valid Go code

### "Empty call graph" (Stage 3)
- Functions may be isolated (no internal calls)
- Check if functions call stdlib only (filtered out)
- Most calls may be to external packages

### "Entry points not detected" (Stage 3.5)
- Verify main.go exists for CLI apps
- Check HTTP handler signatures match patterns
- Review unit_type classification in dataset

### "CodeQL errors" (Stage 3.6)
- Ensure CodeQL CLI is installed: `codeql version`
- Install Go queries: `codeql pack download codeql/go-queries`
- Check Go modules can resolve: `go mod download`

### "LLM errors" (Stage 4)
- Verify `ANTHROPIC_API_KEY` is set
- Check API rate limits
- Review error messages in output

---

## Version History

- **2026-01-12**: Initial implementation
  - Go binary with 4 stages: scan, extract, callgraph, generate
  - Python orchestrator with 4 processing levels
  - Entry point detection for Go patterns
  - CodeQL integration for Go security queries
  - Tested on object-browser (1,433 units, 92.3% reachability reduction)

- **2026-01-12**: Stage 2 verification tested (4 CodeQL-flagged units)
  - Ran full OpenAnt two-stage analysis on 4 CodeQL-flagged units
  - Enhanced Stage 2 with exploit path tracing
  - All 4 CodeQL findings determined to be false positives
  - Results documented in `OBJECT_BROWSER_VULNERABILITY_REPORT.md`

- **2026-01-14**: Attacker simulation approach eliminates all false positives
  - Analyzed 25 units (exploitable + vulnerable_internal from agentic classification)
  - Final results: 0 VULNERABLE, 23 SAFE, 2 PROTECTED
  - Key breakthrough: Changed Stage 2 from "code analysis mode" to "attacker simulation mode"
  - Prompt: "You are an attacker with only a browser. Try to exploit this step by step."
  - All theoretical vulnerabilities correctly identified as unexploitable:
    - Symlink attacks require filesystem access attackers don't have
    - Admin-controlled inputs (CLI args, config files) not attacker-accessible
    - Platform security boundaries (S3 ACLs) prevent exploitation
  - Verification prompts moved from `utilities/` to `prompts/verification_prompts.py`
  - Full results in `OBJECT_BROWSER_VULNERABILITY_REPORT.md`
