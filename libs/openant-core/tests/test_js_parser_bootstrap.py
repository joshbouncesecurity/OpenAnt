"""Tests for the JS parser's lazy npm-install bootstrap.

Covers `_ensure_js_parser_dependencies` in core.parser_adapter: behavior when
node_modules is present, missing, npm is unavailable, or `npm install` fails.
These tests monkeypatch subprocess and shutil.which so they don't need Node.
"""
from pathlib import Path

import pytest

from core import parser_adapter


@pytest.fixture
def fake_parser_dir(tmp_path, monkeypatch):
    """Point _JS_PARSER_DIR at a tmp dir so tests don't touch the real one."""
    monkeypatch.setattr(parser_adapter, "_JS_PARSER_DIR", tmp_path)
    return tmp_path


def test_skips_install_when_node_modules_present(fake_parser_dir, monkeypatch):
    (fake_parser_dir / "node_modules").mkdir()

    calls = []
    monkeypatch.setattr(parser_adapter.subprocess, "run", lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == []


def test_runs_npm_install_when_node_modules_missing(fake_parser_dir, monkeypatch):
    calls = []

    class _Ok:
        returncode = 0

    def _fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _Ok()

    monkeypatch.setattr(parser_adapter.subprocess, "run", _fake_run)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert cmd == ["/usr/bin/npm", "install"]
    assert kwargs["cwd"] == str(fake_parser_dir)


def test_raises_when_npm_not_on_path(fake_parser_dir, monkeypatch):
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="npm"):
        parser_adapter._ensure_js_parser_dependencies()


def test_raises_when_npm_install_fails(fake_parser_dir, monkeypatch):
    class _Fail:
        returncode = 1

    monkeypatch.setattr(parser_adapter.subprocess, "run", lambda *a, **kw: _Fail())
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    with pytest.raises(RuntimeError, match="npm install.*exit code 1"):
        parser_adapter._ensure_js_parser_dependencies()


def test_parse_javascript_surfaces_bootstrap_error(fake_parser_dir, monkeypatch):
    """When bootstrap fails, _parse_javascript must not run the Node subprocess."""
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: None)

    ran_node = []
    monkeypatch.setattr(
        parser_adapter.subprocess,
        "run",
        lambda *a, **kw: ran_node.append((a, kw)),
    )

    with pytest.raises(RuntimeError, match="npm"):
        parser_adapter._parse_javascript(
            repo_path="/tmp/fake-repo",
            output_dir="/tmp/fake-out",
            processing_level="all",
        )

    assert ran_node == [], "Node subprocess should not run when bootstrap fails"
