# Python Parser Technical Reference

**Purpose:** This document is for Claude to read after context compaction to understand the Python parser implementation.

## Quick Context

This is the Python code parser for OpenAnt (a SAST tool). It mirrors the JavaScript parser in `/Users/nahumkorda/code/openant/parsers/javascript/`.

**Goal:** Parse Python repositories into self-contained analysis units for vulnerability detection.

## Architecture

```
parse_repository.py (orchestrator)
    ├── repository_scanner.py   → Finds all .py files
    ├── function_extractor.py   → Extracts functions + module-level code
    ├── call_graph_builder.py   → Builds call relationships
    └── unit_generator.py       → Creates final dataset
```

## Key Implementation Details

### 1. Repository Scanner (`repository_scanner.py`)

**Class:** `RepositoryScanner`

**Key method:** `scan()` → Returns dict with `files` list

**Excludes:** `__pycache__`, `venv`, `.venv`, `.git`, `node_modules`, `site-packages`, etc.

### 2. Function Extractor (`function_extractor.py`)

**Class:** `FunctionExtractor`

**Critical feature:** Module-level code extraction

```python
def extract_module_level_code(self, tree, content, file_path):
    """
    Creates synthetic __module__ unit for code outside functions/classes.

    This is CRITICAL for Streamlit apps and scripts where main logic
    is at module level, not in functions.

    Example vulnerable code this catches:
        vis_params = st.text_input("Enter params")
        vis_params = eval(vis_params)  # At module level, not in function
    """
```

**Function ID format:** `relative/path/file.py:function_name` or `file.py:ClassName.method_name`

**Module-level ID:** `file.py:__module__`

**Unit types assigned:**
- `function` - standalone functions
- `method` - class methods
- `module_level` - code outside functions/classes
- `route_handler` - Flask/Django routes (detected by decorators)
- `constructor`, `property`, `static_method`, `class_method`, `dunder_method`

### 3. Call Graph Builder (`call_graph_builder.py`)

**Class:** `CallGraphBuilder`

**Key data structures:**
```python
self.call_graph = {}           # func_id → [called_func_ids]
self.reverse_call_graph = {}   # func_id → [caller_func_ids]
self.functions_by_name = {}    # simple_name → [func_ids]
self.functions_by_file = {}    # file_path → [func_ids]
self.methods_by_class = {}     # "file:ClassName" → [method_ids]
```

**Call resolution order:**
1. Same file functions
2. Imported modules/functions
3. Class methods (for `self.method()` calls)

**Skips:** Python builtins (`print`, `len`, `range`, etc.), common methods (`append`, `strip`, etc.)

### 4. Unit Generator (`unit_generator.py`)

**Class:** `UnitGenerator`

**Key method:** `assemble_enhanced_code()` - Combines primary code with dependencies

**File boundary marker:**
```python
FILE_BOUNDARY = '\n\n# ========== File Boundary ==========\n\n'
```

**Output format matches OpenAnt's experiment.py expectations:**
```python
{
    "id": "file.py:func",
    "unit_type": "function",
    "code": {
        "primary_code": "... enhanced with deps ...",
        "primary_origin": {
            "file_path": "file.py",
            "enhanced": True,
            "files_included": [...]
        },
        "dependency_metadata": {
            "total_upstream": N,
            "total_downstream": M
        }
    },
    "ground_truth": {"status": "UNKNOWN"},
    "metadata": {...}
}
```

## Test Repository

**Location:** `/Users/nahumkorda/code/test_repos/streamlit-geospatial`

**Commit:** `3f9b00a` (vulnerable version before security fix)

**Known vulnerabilities:**
- 9 instances of `eval()` on user input
- SSRF via unrestricted URL loading

**Test command:**
```bash
cd /Users/nahumkorda/code/openant/parsers/python
python parse_repository.py /Users/nahumkorda/code/test_repos/streamlit-geospatial \
    --output /tmp/test_dataset.json
```

**Verification:**
```python
# All files with eval() should be captured:
# - pages/10_🌍_Earth_Engine_Datasets.py (2 eval calls)
# - pages/1_📷_Timelapse.py (5 eval calls)
# - pages/7_📦_Web_Map_Service.py (1 ast.literal_eval)
# - pages/8_🏜️_Raster_Data_Visualization.py (1 eval - MODULE LEVEL)
```

## Common Issues & Solutions

### Issue: Module-level code not captured
**Solution:** `extract_module_level_code()` in `function_extractor.py` creates `__module__` units

### Issue: eval() in Streamlit apps missed
**Cause:** Streamlit apps often have code at module level, not in functions
**Solution:** Module-level extraction now captures this

### Issue: Import resolution fails
**Cause:** Complex relative imports or missing files
**Solution:** Falls back to name-based matching across files

## Relationship to JavaScript Parser

The Python parser mirrors the JavaScript parser structure:

| JavaScript | Python |
|------------|--------|
| `repository_scanner.js` | `repository_scanner.py` |
| `typescript_analyzer.js` | `function_extractor.py` |
| `dependency_resolver.js` | `call_graph_builder.py` |
| `unit_generator.js` | `unit_generator.py` |

## Future Improvements

1. **Type inference** - Use type hints to improve call resolution
2. **Dataclass support** - Better handling of `@dataclass` decorated classes
3. **Async comprehension** - Track async generators and comprehensions
4. **Cross-file class inheritance** - Resolve parent class methods

## Stage 2 Verification Support

The parser generates `analyzer_output.json` for Stage 2 verification:

```bash
python parse_repository.py /path/to/repo \
    --output dataset.json \
    --analyzer-output analyzer_output.json
```

**Format:** Compatible with `RepositoryIndex` class in `utilities/agentic_enhancer/repository_index.py`

**Enables tools:**
- `search_usages(name)` - Find functions that call a given function
- `search_definitions(name)` - Find function definitions by name
- `read_function(id)` - Get full function code by ID
- `list_functions(file)` - List all functions in a file

## Usage in OpenAnt

After parsing, run vulnerability analysis:

```bash
cd /Users/nahumkorda/code/openant

# Stage 1 only
python experiment.py --dataset geospatial_vuln12

# Stage 1 + Stage 2 verification (recommended)
python experiment.py --dataset geospatial_vuln12 --verify --verify-verbose
```

## Key Files to Read

When resuming work on the parser:

1. **This file** - Technical overview
2. `function_extractor.py:311-421` - Module-level extraction logic
3. `call_graph_builder.py:60-160` - Call graph building
4. `unit_generator.py:52-120` - Unit assembly logic

## Statistics from Test Run

**Parsing Results (streamlit-geospatial):**
```
- 16 Python files
- 44 total units (29 functions + 15 module-level)
- 27 call graph edges
- 12 units containing eval()
- 100% vulnerability coverage
```

**Vulnerability Analysis Results (geospatial_vuln12):**
```
Stage 1 Detection:
- 10 vulnerable, 1 bypassable, 1 parse error (fixed by JSON corrector)

Stage 2 Verification:
- Agreed: 9/11 units
- Corrected: 2 false positives → safe

Final Verdicts:
- 8 vulnerable (eval RCE confirmed)
- 1 bypassable
- 2 safe (Stage 2 corrections)
```
