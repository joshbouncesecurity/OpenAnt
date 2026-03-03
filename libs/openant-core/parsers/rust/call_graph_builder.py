#!/usr/bin/env python3
"""
Call Graph Builder for Rust Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the Rust parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "src/main.rs:main": ["src/lib.rs:Config::new", "src/lib.rs:run"],
            ...
        },
        "reverse_call_graph": {
            "src/lib.rs:Config::new": ["src/main.rs:main"],
            ...
        },
        "statistics": {
            "total_edges": 500,
            "avg_out_degree": 2.5,
            "max_out_degree": 15,
            "isolated_functions": 20
        }
    }
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import tree_sitter_rust as ts_rust
from tree_sitter import Language, Parser


RUST_LANGUAGE = Language(ts_rust.language())

# Rust builtins, macros, and common methods to filter out
RUST_BUILTINS = {
    # Macros (commonly used)
    'println', 'print', 'eprintln', 'eprint', 'format', 'write', 'writeln',
    'vec', 'panic', 'todo', 'unimplemented', 'unreachable',
    'assert', 'assert_eq', 'assert_ne', 'debug_assert', 'debug_assert_eq',
    'dbg', 'env', 'option_env', 'concat', 'stringify', 'include', 'include_str',
    'include_bytes', 'file', 'line', 'column', 'module_path',
    'cfg', 'cfg_attr', 'derive', 'test', 'bench',
    # Standard library common methods
    'clone', 'to_string', 'to_owned', 'into', 'from', 'as_ref', 'as_mut',
    'borrow', 'borrow_mut', 'deref', 'deref_mut',
    'unwrap', 'expect', 'unwrap_or', 'unwrap_or_else', 'unwrap_or_default',
    'ok', 'err', 'ok_or', 'ok_or_else',
    'map', 'map_err', 'map_or', 'map_or_else', 'and_then', 'or_else',
    'filter', 'filter_map', 'find', 'find_map', 'position',
    'collect', 'iter', 'into_iter', 'iter_mut',
    'len', 'is_empty', 'capacity',
    'push', 'pop', 'insert', 'remove', 'get', 'get_mut',
    'contains', 'contains_key', 'entry',
    'first', 'last', 'nth', 'take', 'skip', 'step_by',
    'enumerate', 'zip', 'chain', 'flatten', 'flat_map',
    'fold', 'reduce', 'sum', 'product', 'count',
    'any', 'all', 'min', 'max', 'min_by', 'max_by', 'min_by_key', 'max_by_key',
    'sort', 'sort_by', 'sort_by_key', 'reverse', 'rev',
    'split', 'split_at', 'split_whitespace', 'lines', 'chars', 'bytes',
    'trim', 'trim_start', 'trim_end', 'strip_prefix', 'strip_suffix',
    'starts_with', 'ends_with', 'contains', 'replace', 'replacen',
    'parse', 'try_into', 'try_from',
    # Type conversions
    'as_bytes', 'as_str', 'as_slice', 'as_ptr', 'as_mut_ptr',
    'to_vec', 'to_lowercase', 'to_uppercase', 'to_ascii_lowercase', 'to_ascii_uppercase',
    # Memory/allocation
    'drop', 'forget', 'take', 'replace', 'swap', 'mem',
    'box', 'Box', 'Rc', 'Arc', 'Cell', 'RefCell', 'Mutex', 'RwLock',
    # Common trait methods
    'default', 'Default', 'eq', 'ne', 'lt', 'le', 'gt', 'ge', 'cmp', 'partial_cmp',
    'hash', 'fmt', 'display', 'debug',
    # Async
    'await', 'poll', 'spawn', 'block_on',
    # Result/Option specific
    'is_some', 'is_none', 'is_ok', 'is_err',
    'transpose', 'flatten',
    # Logging (common crates)
    'info', 'warn', 'error', 'debug', 'trace', 'log',
    # Testing
    'assert', 'assert_eq', 'assert_ne',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted Rust function data.

    This is Stage 3 of the Rust parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = extractor_output.get('functions', {})
        self.classes = extractor_output.get('classes', {})  # impl blocks
        self.imports = extractor_output.get('imports', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}
        self.methods_by_impl: Dict[str, List[str]] = {}

        self._build_indexes()

        # Parser for re-parsing function bodies
        self.rust_parser = Parser(RUST_LANGUAGE)

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                if name not in self.functions_by_name:
                    self.functions_by_name[name] = []
                self.functions_by_name[name].append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

            class_name = func_data.get('class_name')  # impl block name
            if class_name:
                impl_key = f"{file_path}:{class_name}"
                if impl_key not in self.methods_by_impl:
                    self.methods_by_impl[impl_key] = []
                self.methods_by_impl[impl_key].append(func_id)

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a Rust builtin or common method."""
        return name in RUST_BUILTINS

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        caller_func = self.functions.get(caller_id, {})
        caller_impl = caller_func.get('class_name')

        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = self.rust_parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'call_expression':
                resolved = self._resolve_call_node(node, code_bytes, caller_file, caller_impl)
                if resolved:
                    calls.add(resolved)
            elif node.type == 'method_call_expression':
                resolved = self._resolve_method_call(node, code_bytes, caller_file, caller_impl)
                if resolved:
                    calls.add(resolved)
            stack.extend(reversed(node.children))

        return calls

    def _resolve_call_node(self, node, source: bytes, caller_file: str,
                           caller_impl: Optional[str]) -> Optional[str]:
        """Resolve a tree-sitter call_expression node to a function ID.

        Handles:
        - foo() - simple function call
        - Type::method() - associated function call
        - self.method() - method call on self (handled by method_call_expression)
        """
        function_node = node.child_by_field_name('function')
        if function_node is None:
            return None

        func_text = source[function_node.start_byte:function_node.end_byte].decode('utf-8', errors='replace')

        # Skip macros (end with !)
        if func_text.rstrip().endswith('!'):
            return None

        # Type::method() pattern
        if '::' in func_text:
            parts = func_text.split('::')
            if len(parts) >= 2:
                type_name = parts[-2]
                method_name = parts[-1]

                if self._is_builtin(method_name):
                    return None

                return self._resolve_associated_call(type_name, method_name, caller_file)

        # Simple function call: foo()
        func_name = func_text.strip()
        if self._is_builtin(func_name):
            return None

        return self._resolve_simple_call(func_name, caller_file, caller_impl)

    def _resolve_method_call(self, node, source: bytes, caller_file: str,
                             caller_impl: Optional[str]) -> Optional[str]:
        """Resolve method_call_expression: receiver.method()"""
        # Get method name
        method_node = node.child_by_field_name('name')
        if method_node is None:
            return None

        method_name = source[method_node.start_byte:method_node.end_byte].decode('utf-8', errors='replace')

        if self._is_builtin(method_name):
            return None

        # Get receiver
        receiver_node = node.child_by_field_name('value')
        if receiver_node:
            receiver_text = source[receiver_node.start_byte:receiver_node.end_byte].decode('utf-8', errors='replace')

            # self.method() - same impl block
            if receiver_text == 'self' and caller_impl:
                return self._resolve_self_call(method_name, caller_file, caller_impl)

            # Self::method() handled by call_expression

        # Can't resolve receiver type statically, try unique name match
        candidates = self.functions_by_name.get(method_name, [])
        # Prefer methods over standalone functions
        method_candidates = [c for c in candidates if self.functions.get(c, {}).get('class_name')]
        if len(method_candidates) == 1:
            return method_candidates[0]

        return None

    def _resolve_simple_call(self, func_name: str, caller_file: str,
                             caller_impl: Optional[str]) -> Optional[str]:
        """Resolve a simple function call to a function ID."""
        # 1. Check same impl block first (implicit self for associated functions)
        if caller_impl:
            result = self._resolve_self_call(func_name, caller_file, caller_impl)
            if result:
                return result

        # 2. Check same file (module-level functions)
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == func_name and not func_data.get('class_name'):
                return func_id

        # 3. Check use-imported items
        file_imports = self.imports.get(caller_file, {})
        if func_name in file_imports:
            # Try to find the actual function
            for func_id in self.functions_by_name.get(func_name, []):
                return func_id

        # 4. Unique name match across files (standalone functions only)
        candidates = self.functions_by_name.get(func_name, [])
        standalone = [c for c in candidates if not self.functions.get(c, {}).get('class_name')]
        if len(standalone) == 1:
            return standalone[0]

        return None

    def _resolve_self_call(self, method_name: str, caller_file: str,
                           caller_impl: str) -> Optional[str]:
        """Resolve a self.method() or Self::method() call within an impl block."""
        impl_key = f"{caller_file}:{caller_impl}"
        impl_methods = self.methods_by_impl.get(impl_key, [])

        for func_id in impl_methods:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == method_name:
                return func_id

        return None

    def _resolve_associated_call(self, type_name: str, method_name: str,
                                 caller_file: str) -> Optional[str]:
        """Resolve a Type::method() associated function call."""
        # Check same file first
        impl_key = f"{caller_file}:{type_name}"
        if impl_key in self.methods_by_impl:
            for func_id in self.methods_by_impl[impl_key]:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        # Check all files for the type
        for key, func_ids in self.methods_by_impl.items():
            if key.endswith(f":{type_name}"):
                for func_id in func_ids:
                    func_data = self.functions.get(func_id, {})
                    if func_data.get('name') == method_name:
                        return func_id

        return None

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction for unparseable code."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        # Match function calls: name(
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(]'
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip Rust keywords
            if func_name in ('if', 'else', 'match', 'while', 'for', 'loop',
                             'fn', 'struct', 'enum', 'impl', 'trait', 'mod',
                             'use', 'pub', 'let', 'mut', 'const', 'static',
                             'return', 'break', 'continue', 'async', 'await',
                             'where', 'type', 'unsafe', 'extern', 'crate', 'self', 'Self'):
                continue
            if not self._is_builtin(func_name):
                resolved = self._resolve_simple_call(func_name, caller_file, None)
                if resolved:
                    calls.add(resolved)

        return calls

    def build_call_graph(self) -> None:
        """Build the complete call graph for all functions."""
        for func_id, func_data in self.functions.items():
            code = func_data.get('code', '')
            if not code:
                self.call_graph[func_id] = []
                continue

            calls = self._extract_calls_from_code(code, func_id)

            # Filter to valid function IDs (must exist, not self-calls)
            valid_calls = [c for c in calls if c in self.functions and c != func_id]
            self.call_graph[func_id] = valid_calls

            # Build reverse graph
            for called_id in valid_calls:
                if called_id not in self.reverse_call_graph:
                    self.reverse_call_graph[called_id] = []
                if func_id not in self.reverse_call_graph[called_id]:
                    self.reverse_call_graph[called_id].append(func_id)

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all dependencies (callees) for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        dependencies = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            calls = self.call_graph.get(current_id, [])
            for called_id in calls:
                if called_id not in visited:
                    visited.add(called_id)
                    dependencies.append(called_id)
                    queue.append((called_id, current_depth + 1))

        return dependencies

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all callers for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        callers = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            caller_ids = self.reverse_call_graph.get(current_id, [])
            for caller_id in caller_ids:
                if caller_id not in visited:
                    visited.add(caller_id)
                    callers.append(caller_id)
                    queue.append((caller_id, current_depth + 1))

        return callers

    def get_statistics(self) -> Dict:
        """Calculate call graph statistics."""
        total_edges = sum(len(calls) for calls in self.call_graph.values())
        num_funcs = len(self.functions)

        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]

        isolated = sum(1 for f in self.functions
                       if len(self.call_graph.get(f, [])) == 0
                       and len(self.reverse_call_graph.get(f, [])) == 0)

        return {
            'total_functions': num_funcs,
            'total_edges': total_edges,
            'avg_out_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'avg_in_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'max_out_degree': max(out_degrees) if out_degrees else 0,
            'max_in_degree': max(in_degrees) if in_degrees else 0,
            'isolated_functions': isolated,
        }

    def export(self) -> Dict:
        """Export the call graph data."""
        return {
            'repository': self.repo_path,
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted Rust function data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python call_graph_builder.py functions.json
  python call_graph_builder.py functions.json --output call_graph.json
  python call_graph_builder.py functions.json --depth 5
        '''
    )

    parser.add_argument('input_file', help='Function extractor output JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')

    args = parser.parse_args()

    try:
        with open(args.input_file) as f:
            extractor_output = json.load(f)

        print(f"Processing {len(extractor_output.get('functions', {}))} functions...", file=sys.stderr)

        builder = CallGraphBuilder(extractor_output, {'max_depth': args.depth})
        builder.build_call_graph()

        result = builder.export()
        stats = result['statistics']

        print(f"Call graph built:", file=sys.stderr)
        print(f"  Total functions: {stats['total_functions']}", file=sys.stderr)
        print(f"  Total edges: {stats['total_edges']}", file=sys.stderr)
        print(f"  Avg out-degree: {stats['avg_out_degree']}", file=sys.stderr)
        print(f"  Max out-degree: {stats['max_out_degree']}", file=sys.stderr)
        print(f"  Isolated functions: {stats['isolated_functions']}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Output written to: {args.output}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
