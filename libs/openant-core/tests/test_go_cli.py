"""Integration tests for the Go CLI wrapper (openant.exe).

These tests invoke the real compiled binary and verify it correctly
delegates to the Python core. They test the wrapper, not the LLM pipeline —
so they use parse-only commands that don't require an API key.
"""
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path

import pytest

CLI_DIR = Path(__file__).parent.parent.parent.parent / "apps" / "openant-cli"
BINARY_NAME = "openant.exe" if sys.platform == "win32" else "openant"
BINARY = CLI_DIR / BINARY_NAME


def _build_binary():
    """Build the Go CLI binary if it doesn't exist."""
    if BINARY.exists():
        return
    if not shutil.which("go"):
        pytest.skip("Go toolchain not installed")
    result = subprocess.run(
        ["go", "build", "-o", str(BINARY), "."],
        cwd=str(CLI_DIR),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build Go binary:\n{result.stderr}")


@pytest.fixture(autouse=True, scope="session")
def ensure_binary():
    """Build the Go CLI binary once per test session."""
    _build_binary()


def run_cli(*args, env_override=None):
    """Run the openant CLI binary and return the CompletedProcess."""
    env = os.environ.copy()
    # Don't let the test hit any real API
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("OPENANT_LOCAL_CLAUDE", None)
    if env_override:
        env.update(env_override)
    return subprocess.run(
        [str(BINARY)] + list(args),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


class TestVersion:
    def test_version_runs(self):
        result = run_cli("version")
        assert result.returncode == 0
        assert "openant" in result.stderr.lower() or "openant" in result.stdout.lower()

    def test_version_subcommand(self):
        result = run_cli("version")
        assert result.returncode == 0


class TestHelp:
    def test_help(self):
        result = run_cli("--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "scan" in output
        assert "parse" in output

    def test_parse_help(self):
        result = run_cli("parse", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "repository" in output.lower()

    def test_scan_help(self):
        result = run_cli("scan", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "pipeline" in output.lower()


class TestParse:
    def test_parse_python_repo(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
            "--json",
        )
        assert result.returncode == 0

        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_produces_dataset(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        dataset = Path(output_dir) / "dataset.json"
        assert dataset.exists()
        data = json.loads(dataset.read_text())
        assert "units" in data
        assert len(data["units"]) > 0

    def test_parse_auto_detect(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--json",
        )
        assert result.returncode == 0
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_js_repo(self, sample_js_repo, tmp_path):
        """JS parsing via Go CLI."""
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
            "--json",
        )
        assert result.returncode == 0, f"JS parse failed:\n{result.stderr}"
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"

    def test_parse_missing_repo(self, tmp_path):
        result = run_cli(
            "parse", str(tmp_path / "nonexistent"),
            "--output", str(tmp_path / "out"),
        )
        assert result.returncode != 0

    def test_parse_json_output_is_valid(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--json",
        )
        # Should always produce valid JSON on stdout when --json is used
        envelope = json.loads(result.stdout)
        assert "status" in envelope


class TestApiKeyHandling:
    def test_scan_requires_api_key(self, sample_python_repo):
        """Scan should fail without an API key."""
        result = run_cli("scan", sample_python_repo)
        output = result.stderr + result.stdout
        assert result.returncode != 0
        assert "api key" in output.lower()
