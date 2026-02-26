# C/C++ Parser - AI Reference

## Current State

The C/C++ parser is fully implemented with a 4-stage pipeline:
1. `repository_scanner.py` - File discovery
2. `function_extractor.py` - Function extraction via tree-sitter
3. `call_graph_builder.py` - Call graph construction
4. `unit_generator.py` - Dataset generation
5. `test_pipeline.py` - Pipeline orchestrator

## Key Files

| File | Purpose |
|------|---------|
| `parsers/c/repository_scanner.py` | Stage 1: Find C/C++ source files |
| `parsers/c/function_extractor.py` | Stage 2: Extract functions via tree-sitter |
| `parsers/c/call_graph_builder.py` | Stage 3: Build bidirectional call graph |
| `parsers/c/unit_generator.py` | Stage 4: Generate dataset.json + analyzer_output.json |
| `parsers/c/test_pipeline.py` | Pipeline orchestrator with processing levels |

## Dependencies

- `tree-sitter` - Python bindings for tree-sitter
- `tree-sitter-c` - C grammar
- `tree-sitter-cpp` - C++ grammar

## Potential Improvements

1. **Struct-aware analysis** - Track struct definitions and field access for taint analysis
2. **Preprocessor expansion** - Partial macro expansion for better call resolution
3. **Function pointer tracking** - Track assignment of function pointers to identify indirect calls
4. **Cross-TU analysis** - Better resolution across translation units using include graph
5. **Type-aware call resolution** - Use parameter types to disambiguate overloaded functions (C++)

## OpenSSL-Specific Notes

- Heavy macro usage: `OPENSSL_malloc`, `ERR_raise`, `OSSL_PARAM_*`
- Provider architecture with function pointer dispatch tables
- Build system: Perl-based `Configure`, NOT cmake
- Public API: non-static functions in `include/openssl/*.h`
- Some `.c` files are Perl-generated at build time
