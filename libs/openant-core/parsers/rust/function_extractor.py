#!/usr/bin/env python3
"""
Function Extractor for Rust Codebases

Extracts ALL functions, methods, and impl blocks from Rust source files using tree-sitter.
This is Phase 2 of the Rust parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "src/main.rs:main": {
                "name": "main",
                "qualified_name": "main",
                "file_path": "src/main.rs",
                "start_line": 10,
                "end_line": 25,
                "code": "fn main() {...}",
                "class_name": null,
                "module_name": null,
                "parameters": [],
                "is_public": true,
                "is_async": false,
                "unit_type": "function"
            }
        },
        "classes": { ... },
        "imports": { ... },
        "statistics": { ... }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter_rust as ts_rust
from tree_sitter import Language, Parser


RUST_LANGUAGE = Language(ts_rust.language())


class FunctionExtractor:
    """
    Extract all functions and impl blocks from Rust source files using tree-sitter.

    This is Stage 2 of the Rust parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}  # impl blocks (struct/trait impls)
        self.imports: Dict[str, Dict[str, str]] = {}  # use statements

        self.parser = Parser(RUST_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_classes': 0,  # impl blocks
            'total_methods': 0,
            'standalone_functions': 0,
            'async_functions': 0,
            'public_functions': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> bytes:
        """Read and cache file contents as bytes (tree-sitter needs bytes)."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_bytes()
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = b""
        return self.file_cache[path_str]

    def _node_text(self, node, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _get_function_name(self, node, source: bytes) -> Optional[str]:
        """Extract function name from a function_item node."""
        name_node = node.child_by_field_name('name')
        if name_node:
            return self._node_text(name_node, source)
        # Fallback: search for identifier child
        for child in node.children:
            if child.type == 'identifier':
                return self._node_text(child, source)
        return None

    def _get_parameters(self, node, source: bytes) -> List[str]:
        """Extract parameters from a function node."""
        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            return params

        for child in params_node.children:
            if child.type == 'parameter':
                # Get parameter pattern (name)
                pattern_node = child.child_by_field_name('pattern')
                if pattern_node:
                    param_name = self._node_text(pattern_node, source)
                    params.append(param_name)
            elif child.type == 'self_parameter':
                # &self, &mut self, self
                params.append(self._node_text(child, source))

        return params

    def _is_public(self, node, source: bytes) -> bool:
        """Check if a function has pub visibility."""
        # Look for visibility_modifier as first child or sibling
        for child in node.children:
            if child.type == 'visibility_modifier':
                return True
        return False

    def _is_async(self, node, source: bytes) -> bool:
        """Check if a function is async."""
        code = self._node_text(node, source)
        return code.strip().startswith('async ') or 'async fn' in code[:50]

    def _has_test_attribute(self, node, source: bytes) -> bool:
        """Check if a function has #[test] or #[cfg(test)] attribute."""
        # Look for attribute nodes before the function
        parent = node.parent
        if parent is None:
            return False

        # Check siblings before this node for attributes
        found_self = False
        for sibling in parent.children:
            if sibling.id == node.id:
                found_self = True
                break
            if sibling.type == 'attribute_item':
                attr_text = self._node_text(sibling, source)
                if '#[test]' in attr_text or '#[cfg(test)]' in attr_text:
                    return True

        # Also check if inside a #[cfg(test)] module
        current = parent
        while current:
            if current.type == 'mod_item':
                # Check for #[cfg(test)] attribute on the module
                for child in current.children:
                    if child.type == 'attribute_item':
                        attr_text = self._node_text(child, source)
                        if '#[cfg(test)]' in attr_text:
                            return True
            current = current.parent

        return False

    def _has_route_attribute(self, node, source: bytes) -> bool:
        """Check if a function has route handler attributes (actix, axum, rocket)."""
        parent = node.parent
        if parent is None:
            return False

        route_patterns = ['#[get', '#[post', '#[put', '#[delete', '#[patch',
                          '#[route', '#[handler', '#[endpoint']

        for sibling in parent.children:
            if sibling.id == node.id:
                break
            if sibling.type == 'attribute_item':
                attr_text = self._node_text(sibling, source).lower()
                for pattern in route_patterns:
                    if pattern in attr_text:
                        return True

        return False

    def _has_main_attribute(self, node, source: bytes) -> bool:
        """Check if function has async runtime main attributes."""
        parent = node.parent
        if parent is None:
            return False

        main_patterns = ['#[tokio::main', '#[async_std::main', '#[actix_web::main',
                         '#[actix_rt::main', '#[rocket::main', '#[rocket::launch']

        for sibling in parent.children:
            if sibling.id == node.id:
                break
            if sibling.type == 'attribute_item':
                attr_text = self._node_text(sibling, source)
                for pattern in main_patterns:
                    if pattern in attr_text:
                        return True

        return False

    def _classify_function(self, func_name: str, impl_name: Optional[str],
                           module_name: Optional[str], is_public: bool,
                           file_path: str, has_self: bool,
                           is_test: bool, is_route: bool, is_main: bool) -> str:
        """Classify a function by its type/purpose."""
        path_lower = file_path.lower()

        # Test functions
        if is_test or func_name.startswith('test_'):
            return 'test'

        # Constructor patterns
        if func_name in ('new', 'default', 'create', 'init', 'build'):
            return 'constructor'

        # Route handlers
        if is_route:
            return 'route_handler'

        # Entry points
        if func_name == 'main' or is_main:
            return 'entry_point'

        # Method in impl block with self
        if impl_name and has_self:
            return 'method'

        # Associated function (no self, but in impl block)
        if impl_name and not has_self:
            return 'associated_function'

        # Standalone function
        return 'function'

    def _extract_imports(self, tree, source: bytes) -> Dict[str, str]:
        """Extract use statements from a file."""
        imports = {}
        stack = [tree.root_node]

        while stack:
            node = stack.pop()

            if node.type == 'use_declaration':
                # Extract the use path
                use_text = self._node_text(node, source)
                # Parse use statement: use foo::bar::Baz;
                # Store as import_name -> 'use'
                if '::' in use_text:
                    # Get the last part as the imported name
                    parts = use_text.replace('use ', '').replace(';', '').strip()
                    if '{' in parts:
                        # use foo::{bar, baz};
                        base = parts.split('{')[0].rstrip('::')
                        items = parts.split('{')[1].rstrip('}').split(',')
                        for item in items:
                            item = item.strip()
                            if item:
                                imports[item] = f"use {base}::{item}"
                    else:
                        # use foo::bar::Baz;
                        last_part = parts.split('::')[-1]
                        imports[last_part] = use_text.strip()

            stack.extend(reversed(node.children))

        return imports

    def _extract_functions_from_tree(self, tree, source: bytes, file_path: Path,
                                      relative_path: str) -> None:
        """Extract all function definitions from a parsed tree."""
        # Stack-based traversal: (node, impl_name, module_name)
        stack = [(tree.root_node, None, None)]

        while stack:
            node, impl_name, module_name = stack.pop()

            if node.type == 'function_item':
                self._process_function_node(
                    node, source, relative_path, impl_name, module_name
                )

            elif node.type == 'impl_item':
                # Extract impl target (struct/trait name)
                type_node = node.child_by_field_name('type')
                new_impl_name = self._node_text(type_node, source) if type_node else None

                # Check for trait impl: impl Trait for Type
                trait_node = node.child_by_field_name('trait')
                if trait_node:
                    trait_name = self._node_text(trait_node, source)
                    new_impl_name = f"{trait_name} for {new_impl_name}" if new_impl_name else trait_name

                if new_impl_name:
                    impl_id = f"{relative_path}:{new_impl_name}"
                    body_node = node.child_by_field_name('body')
                    methods = []
                    if body_node:
                        for child in body_node.children:
                            if child.type == 'function_item':
                                mname = self._get_function_name(child, source)
                                if mname:
                                    methods.append(mname)

                    self.classes[impl_id] = {
                        'name': new_impl_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'module_name': module_name,
                    }
                    self.stats['total_classes'] += 1

                # Recurse into impl body with updated impl_name
                body_node = node.child_by_field_name('body')
                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, new_impl_name, module_name))
                continue  # Don't walk children again

            elif node.type == 'mod_item':
                # Extract module name
                name_node = node.child_by_field_name('name')
                new_module_name = self._node_text(name_node, source) if name_node else module_name

                # Recurse into module body
                body_node = node.child_by_field_name('body')
                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, impl_name, new_module_name))
                continue  # Don't walk children again

            else:
                for child in reversed(node.children):
                    stack.append((child, impl_name, module_name))

    def _process_function_node(self, node, source: bytes, relative_path: str,
                                impl_name: Optional[str], module_name: Optional[str]) -> None:
        """Process a single function_item node."""
        name = self._get_function_name(node, source)
        if not name:
            return

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
        end_line = node.end_point[0] + 1
        parameters = self._get_parameters(node, source)

        is_public = self._is_public(node, source)
        is_async = self._is_async(node, source)
        is_test = self._has_test_attribute(node, source)
        is_route = self._has_route_attribute(node, source)
        is_main = self._has_main_attribute(node, source)

        # Check if method has self parameter
        has_self = any('self' in p for p in parameters)

        unit_type = self._classify_function(
            name, impl_name, module_name, is_public, relative_path,
            has_self, is_test, is_route, is_main
        )

        # Build qualified name and function ID
        if impl_name:
            qualified_name = f"{impl_name}::{name}"
        elif module_name:
            qualified_name = f"{module_name}::{name}"
        else:
            qualified_name = name

        func_id = f"{relative_path}:{qualified_name}"

        func_data = {
            'name': name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': impl_name,  # In Rust, this is the impl block target
            'module_name': module_name,
            'parameters': parameters,
            'is_public': is_public,
            'is_async': is_async,
            'unit_type': unit_type,
        }

        self.functions[func_id] = func_data
        self.stats['total_functions'] += 1

        if impl_name:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1

        if is_async:
            self.stats['async_functions'] += 1

        if is_public:
            self.stats['public_functions'] += 1

        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    def process_file(self, file_path: Path) -> None:
        """Process a single Rust file."""
        source = self.read_file(file_path)
        if not source:
            self.stats['files_with_errors'] += 1
            return

        relative_path = str(file_path.relative_to(self.repo_path))

        try:
            tree = self.parser.parse(source)
        except Exception as e:
            print(f"Parse error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1

        # Extract imports
        self.imports[relative_path] = self._extract_imports(tree, source)

        # Extract functions
        self._extract_functions_from_tree(tree, source, file_path, relative_path)

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Rust files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            for file_path in self.repo_path.rglob('*.rs'):
                path_str = str(file_path)
                if any(excl in path_str for excl in ['.git', 'target', '.cargo', 'vendor']):
                    continue
                self.process_file(file_path)

        return self.export()

    def export(self) -> Dict:
        """Export extraction results."""
        return {
            'repository': str(self.repo_path),
            'extraction_time': datetime.now().isoformat(),
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all functions and impl blocks from a Rust repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python function_extractor.py /path/to/repo
  python function_extractor.py /path/to/repo --output functions.json
  python function_extractor.py /path/to/repo --scan-file scan_results.json
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--scan-file', help='Use file list from repository scanner output')

    args = parser.parse_args()

    try:
        extractor = FunctionExtractor(args.repo_path)

        if args.scan_file:
            with open(args.scan_file) as f:
                scan_result = json.load(f)
            result = extractor.extract_from_scan(scan_result)
        else:
            result = extractor.extract_all()

        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Extraction complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total functions: {result['statistics']['total_functions']}", file=sys.stderr)
            print(f"  Standalone: {result['statistics']['standalone_functions']}", file=sys.stderr)
            print(f"  Methods: {result['statistics']['total_methods']}", file=sys.stderr)
            print(f"  Async: {result['statistics']['async_functions']}", file=sys.stderr)
            print(f"  Public: {result['statistics']['public_functions']}", file=sys.stderr)
            print(f"Total impl blocks: {result['statistics']['total_classes']}", file=sys.stderr)
            print(f"Files processed: {result['statistics']['files_processed']}", file=sys.stderr)
            if result['statistics']['files_with_errors'] > 0:
                print(f"Files with errors: {result['statistics']['files_with_errors']}", file=sys.stderr)
            print(f"By type:", file=sys.stderr)
            for unit_type, count in sorted(result['statistics']['by_type'].items()):
                print(f"  {unit_type}: {count}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
