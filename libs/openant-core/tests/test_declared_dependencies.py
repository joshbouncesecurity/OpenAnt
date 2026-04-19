"""Guard against pyproject.toml declared deps drifting from actual imports.

Regression guard for the Claude Agent SDK migration (#25), which dropped
`anthropic` from pyproject.toml while leaving `import anthropic` live in
four files. Every clean install of openant broke at `openant parse`.
"""
import ast
import sys
import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
PACKAGED_DIRS = ["openant", "core", "utilities", "parsers", "prompts", "context", "report"]

# Maps PyPI distribution names to their top-level import names when they differ.
# Extend only when adding a new dependency whose import name diverges from its
# PyPI name; the test will tell you which direction it's failing.
DIST_TO_IMPORT = {
    "python-dotenv": "dotenv",
    "pyyaml": "yaml",
    "claude-agent-sdk": "claude_agent_sdk",
    "tree-sitter": "tree_sitter",
    "tree-sitter-c": "tree_sitter_c",
    "tree-sitter-cpp": "tree_sitter_cpp",
    "tree-sitter-ruby": "tree_sitter_ruby",
    "tree-sitter-php": "tree_sitter_php",
}


def _dist_name_to_import(dist: str) -> str:
    key = dist.lower().replace("_", "-")
    return DIST_TO_IMPORT.get(key, dist.replace("-", "_").lower())


def _declared_imports() -> set[str]:
    with open(PROJECT_ROOT / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    deps = data["project"]["dependencies"]
    names = []
    for dep in deps:
        for sep in ("[", ">=", "<=", "==", "!=", ">", "<", "~=", ";", " "):
            dep = dep.split(sep, 1)[0]
        names.append(dep.strip())
    return {_dist_name_to_import(n) for n in names if n}


def _collect_top_level_imports(root: Path) -> set[str]:
    """Return the set of top-level module names imported anywhere under `root`."""
    imports: set[str] = set()
    for py in root.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom):
                # Relative imports (level > 0) have module=None or point at a
                # sibling — they can't be third-party by definition.
                if node.level == 0 and node.module:
                    imports.add(node.module.split(".", 1)[0])
    return imports


def _first_party_names() -> set[str]:
    """Every module/package name reachable in the repo — treated as first-party.

    Parsers use sys.path hackery to import siblings as top-level names
    (e.g. `from call_graph_builder import ...`), so the set of first-party
    names isn't just the packaged top-level dirs.
    """
    names: set[str] = set(PACKAGED_DIRS)
    for path in PROJECT_ROOT.rglob("*.py"):
        # Skip the managed dev venv and any other nested virtualenvs.
        if ".venv" in path.parts or "site-packages" in path.parts:
            continue
        names.add(path.stem)
        for parent in path.parents:
            if parent == PROJECT_ROOT:
                break
            names.add(parent.name)
    return names


def test_every_third_party_import_is_declared():
    first_party = _first_party_names()
    stdlib = set(sys.stdlib_module_names)
    declared = _declared_imports()

    all_imports: set[str] = set()
    for pkg in PACKAGED_DIRS:
        pkg_dir = PROJECT_ROOT / pkg
        if pkg_dir.is_dir():
            all_imports |= _collect_top_level_imports(pkg_dir)

    # Deps pulled in transitively that some callsites import by name. These
    # aren't direct deps of openant but are guaranteed present by something
    # we *do* declare, so it's safe to treat them as allowed.
    transitive_allowed = {
        # pulled in by claude-agent-sdk
        "mcp",
    }

    third_party = all_imports - first_party - stdlib - transitive_allowed
    missing = sorted(third_party - declared)
    assert not missing, (
        f"Imports not declared in pyproject.toml dependencies: {missing}. "
        "Either add the distribution to `dependencies`, or remove the import. "
        "If a distribution's import name differs from its PyPI name, add it to "
        "DIST_TO_IMPORT in this test."
    )


@pytest.mark.parametrize("pkg", PACKAGED_DIRS)
def test_package_imports_cleanly(pkg):
    """Smoke-test: every packaged top-level module can be imported.

    This catches the specific failure mode from #25 — where a dropped dep
    only manifested at `import utilities` time, not at `import openant`.
    """
    if not (PROJECT_ROOT / pkg).is_dir():
        pytest.skip(f"{pkg} not present")
    __import__(pkg)
