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

REPO_ROOT = Path(__file__).parent.parent.parent.parent
CLI_DIR = REPO_ROOT / "apps" / "openant-cli"
BINARY_NAME = "openant.exe" if sys.platform == "win32" else "openant"

# Build into .build/ within the repo (gitignored) to avoid polluting source dirs.
_BUILD_DIR = REPO_ROOT / ".build"
BINARY = _BUILD_DIR / BINARY_NAME


def _build_binary():
    """Build the Go CLI binary into .build/ within the repo."""
    if BINARY.exists():
        return
    if not shutil.which("go"):
        pytest.skip("Go toolchain not installed")
    _BUILD_DIR.mkdir(exist_ok=True)
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
    """Build the Go CLI binary once per test session, clean up after."""
    _build_binary()
    yield
    # Clean up build artifacts
    if _BUILD_DIR.exists():
        shutil.rmtree(_BUILD_DIR, ignore_errors=True)


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


class TestParsePython:
    """Integration tests for parsing Python repos via the Go CLI."""

    def test_parse_succeeds(self, sample_python_repo, tmp_path):
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

    def test_produces_dataset_and_analyzer_output(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        assert (Path(output_dir) / "dataset.json").exists()
        assert (Path(output_dir) / "analyzer_output.json").exists()

    def test_dataset_has_units(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        assert "units" in data
        assert len(data["units"]) > 0

    def test_units_have_code_and_id(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        for unit in data["units"]:
            assert "id" in unit, f"Unit missing 'id': {unit}"
            assert "code" in unit, f"Unit missing 'code': {unit}"

    def test_finds_flask_route_handlers(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
            "--level", "all",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        unit_ids = [u["id"] for u in data["units"]]
        # Sample repo has get_user_endpoint and create_user_endpoint
        assert any("get_user_endpoint" in uid for uid in unit_ids)
        assert any("create_user_endpoint" in uid for uid in unit_ids)

    def test_auto_detects_python(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--json",
        )
        assert result.returncode == 0
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"
        assert envelope["data"]["language"] == "python"

    def test_produces_step_report(self, sample_python_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_python_repo,
            "--output", output_dir,
            "--language", "python",
        )
        report = Path(output_dir) / "parse.report.json"
        assert report.exists()
        data = json.loads(report.read_text())
        assert data["step"] == "parse"
        assert data["status"] == "success"


class TestParseJavaScript:
    """Integration tests for parsing JavaScript repos via the Go CLI."""

    def test_parse_succeeds(self, sample_js_repo, tmp_path):
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

    def test_produces_dataset_and_analyzer_output(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
        )
        assert (Path(output_dir) / "dataset.json").exists()
        assert (Path(output_dir) / "analyzer_output.json").exists()

    def test_dataset_has_units(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
            "--level", "all",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        assert "units" in data
        assert len(data["units"]) > 0

    def test_units_have_code_and_id(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
            "--level", "all",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        for unit in data["units"]:
            assert "id" in unit, f"Unit missing 'id': {unit}"
            assert "code" in unit, f"Unit missing 'code': {unit}"

    def test_finds_known_functions(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
            "--level", "all",
        )
        data = json.loads((Path(output_dir) / "dataset.json").read_text())
        unit_ids = [u["id"] for u in data["units"]]
        # Sample repo has getUser, createUser, getConnection
        assert any("getUser" in uid for uid in unit_ids)
        assert any("createUser" in uid for uid in unit_ids)
        assert any("getConnection" in uid for uid in unit_ids)

    def test_auto_detects_javascript(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        result = run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--json",
        )
        assert result.returncode == 0, f"JS auto-detect failed:\n{result.stderr}"
        envelope = json.loads(result.stdout)
        assert envelope["status"] == "success"
        assert envelope["data"]["language"] == "javascript"

    def test_produces_step_report(self, sample_js_repo, tmp_path):
        output_dir = str(tmp_path / "output")
        run_cli(
            "parse", sample_js_repo,
            "--output", output_dir,
            "--language", "javascript",
        )
        report = Path(output_dir) / "parse.report.json"
        assert report.exists()
        data = json.loads(report.read_text())
        assert data["step"] == "parse"
        assert data["status"] == "success"


class TestInit:
    """Tests for `openant init` with auto-detect and non-git support."""

    @pytest.fixture
    def isolated_home(self, tmp_path):
        """Override home directory so init doesn't pollute real ~/.openant/."""
        home = str(tmp_path / "fakehome")
        os.makedirs(home)
        # USERPROFILE for Windows, HOME for Unix
        return {"USERPROFILE": home, "HOME": home}

    def _read_project_json(self, home_dir, project_name):
        """Read project.json created by init."""
        project_json = Path(home_dir) / ".openant" / "projects" / project_name / "project.json"
        assert project_json.exists(), f"project.json not found at {project_json}"
        return json.loads(project_json.read_text())

    def test_init_auto_detect_python(self, sample_python_repo, isolated_home, tmp_path):
        """Init without -l should auto-detect Python."""
        result = run_cli(
            "init", sample_python_repo,
            "--name", "test/python-repo",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: python" in result.stderr
        assert "python" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/python-repo",
        )
        assert project["language"] == "python"

    def test_init_auto_detect_javascript(self, sample_js_repo, isolated_home, tmp_path):
        """Init without -l should auto-detect JavaScript."""
        result = run_cli(
            "init", sample_js_repo,
            "--name", "test/js-repo",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Detected language: javascript" in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/js-repo",
        )
        assert project["language"] == "javascript"

    def test_init_explicit_language(self, sample_python_repo, isolated_home):
        """Init with explicit -l should use specified language."""
        result = run_cli(
            "init", sample_python_repo,
            "--name", "test/explicit-lang",
            "-l", "go",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "Auto-detecting" not in result.stderr

        project = self._read_project_json(
            isolated_home["HOME"], "test/explicit-lang",
        )
        assert project["language"] == "go"

    def test_init_non_git_directory(self, tmp_path, isolated_home):
        """Init on a plain directory (no .git) should work with 'nogit' commit."""
        repo = tmp_path / "plain_repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        result = run_cli(
            "init", str(repo),
            "--name", "test/no-git",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"

        project = self._read_project_json(
            isolated_home["HOME"], "test/no-git",
        )
        assert project["language"] == "python"
        assert project["commit_sha"] == "nogit"
        assert project["commit_sha_short"] == "nogit"

    def test_init_non_git_ignores_commit_flag(self, tmp_path, isolated_home):
        """--commit on a non-git directory should warn and use 'nogit'."""
        repo = tmp_path / "plain_repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')")

        result = run_cli(
            "init", str(repo),
            "--name", "test/no-git-commit",
            "--commit", "abc123",
            env_override=isolated_home,
        )
        assert result.returncode == 0, f"init failed:\n{result.stderr}"
        assert "ignored" in result.stderr.lower()

        project = self._read_project_json(
            isolated_home["HOME"], "test/no-git-commit",
        )
        assert project["commit_sha"] == "nogit"

    def test_init_empty_dir_fails(self, tmp_path, isolated_home):
        """Init on an empty directory should fail (no supported source files)."""
        empty = tmp_path / "empty_repo"
        empty.mkdir()

        result = run_cli(
            "init", str(empty),
            "--name", "test/empty",
            env_override=isolated_home,
        )
        assert result.returncode != 0
        assert "no supported source files" in (result.stderr + result.stdout).lower()


class TestGenerateContextHelp:
    """Tests for `openant generate-context --help`."""

    def test_help(self):
        result = run_cli("generate-context", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "repository" in output.lower()
        assert "context" in output.lower()


class TestGenerateContext:
    """Tests for `openant generate-context` (no API key)."""

    def test_requires_api_key(self, sample_python_repo):
        """generate-context should fail without an API key."""
        result = run_cli("generate-context", sample_python_repo)
        output = result.stderr + result.stdout
        assert result.returncode != 0
        assert "api key" in output.lower()


class TestApiKeyHandling:
    def test_scan_requires_api_key(self, sample_python_repo):
        """Scan should fail without an API key."""
        result = run_cli("scan", sample_python_repo)
        output = result.stderr + result.stdout
        assert result.returncode != 0
        assert "api key" in output.lower()
