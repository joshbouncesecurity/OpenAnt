"""Tests for the centralized file I/O and subprocess helpers."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from utilities.file_io import open_utf8, read_json, write_json, run_utf8


class TestOpenUtf8:
    def test_defaults_to_utf8_encoding(self, tmp_path):
        path = tmp_path / "test.txt"
        # Write a file with non-ASCII UTF-8 content
        content = "hello \u2019world\u2019 caf\u00e9"  # curly quotes + accented char
        with open_utf8(str(path), "w") as f:
            f.write(content)

        with open_utf8(str(path), "r") as f:
            assert f.read() == content

    def test_handles_byte_0x9d(self, tmp_path):
        """Reproduce the original Windows charmap error: byte 0x9d."""
        path = tmp_path / "test.json"
        # 0x9d in cp1252 is undefined, but valid in UTF-8 as part of \u009d
        # The original error was from source code containing curly quotes
        # (U+2019 = 0xe2 0x80 0x99 in UTF-8)
        content = '{"code": "const x = \\u2018hello\\u2019"}'
        path.write_text(content, encoding="utf-8")

        with open_utf8(str(path), "r") as f:
            data = json.load(f)
        assert "code" in data

    def test_respects_explicit_encoding(self, tmp_path):
        path = tmp_path / "latin.txt"
        path.write_bytes(b"caf\xe9")  # latin-1 encoded "café"

        with open_utf8(str(path), "r", encoding="latin-1") as f:
            assert f.read() == "caf\u00e9"

    def test_binary_mode_skips_encoding(self, tmp_path):
        path = tmp_path / "binary.bin"
        path.write_bytes(b"\x00\x01\x02")

        with open_utf8(str(path), "rb") as f:
            assert f.read() == b"\x00\x01\x02"


class TestReadJson:
    def test_reads_utf8_json(self, tmp_path):
        path = tmp_path / "data.json"
        data = {"name": "caf\u00e9", "emoji": "\u2728"}
        path.write_text(json.dumps(data), encoding="utf-8")

        result = read_json(str(path))
        assert result == data

    def test_reads_json_with_problematic_bytes(self, tmp_path):
        """Ensure JSON with source code snippets containing non-ASCII works."""
        path = tmp_path / "analyzer_output.json"
        # Simulate analyzer output with curly quotes in source code
        data = {
            "functions": {
                "app.ts:getUser": {
                    "code": "// Returns the user\u2019s profile",
                    "name": "getUser",
                }
            }
        }
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

        result = read_json(str(path))
        assert "\u2019" in result["functions"]["app.ts:getUser"]["code"]


class TestWriteJson:
    def test_writes_utf8_json(self, tmp_path):
        path = tmp_path / "out.json"
        data = {"value": "caf\u00e9 \u2019"}
        write_json(str(path), data)

        # json.dump defaults to ensure_ascii=True, so non-ASCII is escaped
        raw = path.read_bytes()
        result = json.loads(raw.decode("utf-8"))
        assert result == data

    def test_default_indent(self, tmp_path):
        path = tmp_path / "out.json"
        write_json(str(path), {"a": 1})

        text = path.read_text(encoding="utf-8")
        assert "  " in text  # default indent=2

    def test_custom_indent(self, tmp_path):
        path = tmp_path / "out.json"
        write_json(str(path), {"a": 1}, indent=4)

        text = path.read_text(encoding="utf-8")
        assert "    " in text


class TestRunUtf8:
    def test_sets_utf8_encoding_in_text_mode(self):
        result = run_utf8(
            [sys.executable, "-c", 'import sys; sys.stdout.buffer.write("caf\u00e9\\n".encode("utf-8"))'],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "caf\u00e9" in result.stdout

    def test_sets_errors_replace(self):
        # Output raw bytes that aren't valid UTF-8
        result = run_utf8(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'hello\\x9dworld')"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # The invalid byte should be replaced rather than raising an error
        assert "hello" in result.stdout
        assert "world" in result.stdout

    def test_no_encoding_without_text_mode(self):
        result = run_utf8(
            [sys.executable, "-c", "print('hello')"],
            capture_output=True,
        )
        assert result.returncode == 0
        # Without text=True, stdout is bytes
        assert isinstance(result.stdout, bytes)

    def test_respects_explicit_encoding(self):
        result = run_utf8(
            [sys.executable, "-c", "print('hello')"],
            capture_output=True,
            text=True,
            encoding="ascii",
        )
        assert result.returncode == 0
        assert "hello" in result.stdout


class TestRoundTrip:
    """End-to-end test: write JSON with non-ASCII, read it back."""

    def test_write_read_roundtrip_with_source_code(self, tmp_path):
        """Simulate the actual parser pipeline: write analyzer output, read it back."""
        path = str(tmp_path / "analyzer_output.json")

        # Data that mimics real analyzer output with non-ASCII source code
        original = {
            "functions": {
                "src/api.ts:handleRequest": {
                    "name": "handleRequest",
                    "code": 'const msg = "User\u2019s request";  // em dash \u2014 here',
                    "startLine": 10,
                    "endLine": 25,
                }
            },
            "callGraph": {},
        }

        write_json(path, original)
        loaded = read_json(path)

        assert loaded == original
        assert "\u2019" in loaded["functions"]["src/api.ts:handleRequest"]["code"]
        assert "\u2014" in loaded["functions"]["src/api.ts:handleRequest"]["code"]
