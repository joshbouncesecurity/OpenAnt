# Python Code Parser Pipeline

A comprehensive Python code parser that deconstructs codebases into self-contained analysis units for vulnerability detection.

## Overview

The parser transforms a Python repository into a dataset of analysis units, where each unit contains:
- The primary code (function, method, or module-level code)
- All upstream dependencies (functions it calls)
- All downstream callers (functions that call it)
- Metadata for security analysis

## Pipeline Stages

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Repository     │     │   Function      │     │   Call Graph    │     │     Unit        │
│   Scanner       │ ──▶ │   Extractor     │ ──▶ │    Builder      │ ──▶ │   Generator     │
│                 │     │                 │     │                 │     │                 │
│  Find .py files │     │  Extract funcs  │     │  Build call     │     │  Create self-   │
│                 │     │  + module code  │     │  relationships  │     │  contained units│
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Stage 1: Repository Scanner (`repository_scanner.py`)

Scans the repository to find all Python source files.

**Input:** Repository path
**Output:** List of `.py` files with metadata

**Features:**
- Excludes common non-source directories (`__pycache__`, `venv`, `.git`, etc.)
- Optional test file skipping
- File size statistics

**Example:**
```bash
python repository_scanner.py /path/to/repo --output scan.json
```

### Stage 2: Function Extractor (`function_extractor.py`)

Extracts ALL code from Python files using AST parsing.

**Input:** Scan results or repository path
**Output:** Complete function inventory

**Extracts:**
- Standalone functions
- Class methods (including `__init__`, properties, static/class methods)
- **Module-level code** (code outside functions/classes)

**Module-Level Code:**
Many Python applications (especially Streamlit, scripts) have significant code at module level. The extractor creates a synthetic `__module__` unit for each file containing executable module-level code.

**Example:**
```bash
python function_extractor.py /path/to/repo --output functions.json
```

### Stage 3: Call Graph Builder (`call_graph_builder.py`)

Builds bidirectional call graphs by analyzing function bodies.

**Input:** Extractor output
**Output:** Call graph + reverse call graph

**Resolves:**
- Simple function calls: `func_name()`
- Method calls: `self.method()`, `obj.method()`
- Module calls: `module.function()`
- Imported functions

**Call Graphs:**
- **Forward (call_graph):** function → functions it calls
- **Reverse (reverse_call_graph):** function → functions that call it

**Example:**
```bash
python call_graph_builder.py functions.json --output call_graph.json
```

### Stage 4: Unit Generator (`unit_generator.py`)

Creates self-contained analysis units with full context.

**Input:** Call graph data
**Output:** Dataset compatible with OpenAnt

**Each unit contains:**
```json
{
  "id": "file.py:function_name",
  "unit_type": "function|method|module_level|...",
  "code": {
    "primary_code": "... enhanced code with dependencies ...",
    "primary_origin": {
      "file_path": "file.py",
      "start_line": 10,
      "end_line": 25,
      "function_name": "function_name",
      "enhanced": true,
      "files_included": ["file.py", "utils.py"]
    },
    "dependency_metadata": {
      "total_upstream": 5,
      "total_downstream": 2
    }
  }
}
```

**Example:**
```bash
python unit_generator.py call_graph.json --output dataset.json
```

## Quick Start

### One-Command Parsing

Use the orchestrator script for the complete pipeline:

```bash
python parse_repository.py /path/to/repo --output dataset.json
```

### With Stage 2 Verification Support

Generate both dataset and analyzer output for full OpenAnt integration:

```bash
python parse_repository.py /path/to/repo \
    --output dataset.json \
    --analyzer-output analyzer_output.json
```

The `analyzer_output.json` enables Stage 2 verification tools:
- `search_usages` - Find where a function is called
- `search_definitions` - Find function definitions
- `read_function` - Get full function code
- `list_functions` - List functions in a file

### With Intermediate Files

Save intermediate results for debugging:

```bash
python parse_repository.py /path/to/repo \
    --output dataset.json \
    --intermediates /tmp/parsing_debug
```

This saves:
- `scan_result.json` - File list
- `functions.json` - Extracted functions
- `call_graph.json` - Call relationships
- `analyzer_output.json` - Stage 2 verification index
- `dataset.json` - Final units

## Unit Types

| Type | Description |
|------|-------------|
| `function` | Standalone function |
| `method` | Class instance method |
| `static_method` | `@staticmethod` decorated |
| `class_method` | `@classmethod` decorated |
| `property` | `@property` decorated |
| `constructor` | `__init__` method |
| `dunder_method` | Other `__xxx__` methods |
| `route_handler` | Flask/Django route handlers |
| `module_level` | Code outside functions/classes |
| `private_function` | Functions starting with `_` |

## Enhanced Code Assembly

Units include not just the primary code, but also relevant dependencies:

```python
# Primary function
def process_user_input(data):
    validated = validate(data)      # Calls validate()
    return transform(validated)     # Calls transform()

# ========== File Boundary ==========

# Upstream dependency (called by process_user_input)
def validate(data):
    ...

# ========== File Boundary ==========

# Another upstream dependency
def transform(data):
    ...
```

This enables security analysis to understand the full data flow.

## Configuration Options

### Dependency Depth

Control how deep to resolve dependencies:

```bash
python parse_repository.py /path/to/repo --depth 2
```

- `--depth 1`: Direct calls only
- `--depth 3`: Default, 3 levels deep
- `--depth 5`: Extensive context

### Skip Tests

Exclude test files from analysis:

```bash
python parse_repository.py /path/to/repo --skip-tests
```

## Output Format

The final dataset is compatible with OpenAnt's `experiment.py`:

```json
{
  "name": "repository_name",
  "repository": "/path/to/repo",
  "units": [...],
  "statistics": {
    "total_units": 44,
    "by_type": {
      "function": 29,
      "module_level": 15
    },
    "units_with_upstream": 14,
    "units_with_downstream": 26
  }
}
```

## Security Analysis Use Case

The parser was designed to capture vulnerabilities like:

```python
# Module-level code with eval() vulnerability
vis_params = st.text_input("Enter params", "{}")
vis_params = eval(vis_params)  # VULNERABLE: RCE via user input
```

By creating `__module__` units, the parser ensures this code is captured even though it's not inside a function.

## Test Results

The parser has been validated against the streamlit-geospatial repository:

| Metric | Value |
|--------|-------|
| Python files scanned | 16 |
| Total units extracted | 44 |
| Functions | 29 |
| Module-level units | 15 |
| Call graph edges | 27 |
| Units with eval() | 12 |
| Vulnerability coverage | 100% |

All 9 instances of `eval()` on user input were captured, including those at module level.

## Files

```
/Users/nahumkorda/code/openant/parsers/python/
├── parse_repository.py      # Main orchestrator (use this)
├── repository_scanner.py    # Stage 1: Find files
├── function_extractor.py    # Stage 2: Extract code
├── call_graph_builder.py    # Stage 3: Build relationships
├── unit_generator.py        # Stage 4: Create units
├── PARSER_PIPELINE.md       # This file (human documentation)
└── PARSER_UPGRADE_PLAN.md   # Technical reference for Claude
```

## Related Documentation

- `datasets/DATASET_FORMAT.md` - Complete dataset schema
- `datasets/geospatial/` - Example Python dataset
- `CURRENT_IMPLEMENTATION.md` - Project overview
