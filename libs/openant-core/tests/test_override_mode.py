"""Unit tests for the override-mode functionality of generate-context.

These tests cover the Python-side logic for `find_override_file()`,
`gather_context_sources()` merge behavior, and the override-mode dispatch
inside `generate_application_context()`. They do not invoke the LLM —
network calls are mocked or avoided by exercising the early-return paths.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from context.application_context import (
    MANUAL_OVERRIDE_FILES,
    MERGE_CONTEXT_SUPPLEMENT,
    find_override_file,
    gather_context_sources,
    generate_application_context,
)


class TestFindOverrideFile:
    """Tests for the `find_override_file()` helper."""

    def test_returns_none_when_no_override(self, tmp_path):
        """No override files in repo -> returns None."""
        # Create a non-override file to ensure the directory is real
        (tmp_path / "README.md").write_text("# repo")
        assert find_override_file(tmp_path) is None

    def test_finds_openant_md(self, tmp_path):
        """OPENANT.md is detected."""
        path = tmp_path / "OPENANT.md"
        path.write_text("# override")
        result = find_override_file(tmp_path)
        assert result == path

    def test_finds_openant_json(self, tmp_path):
        """OPENANT.json is detected when no OPENANT.md exists."""
        path = tmp_path / "OPENANT.json"
        path.write_text('{"application_type": "web_app"}')
        result = find_override_file(tmp_path)
        assert result == path

    def test_finds_dot_openant_md(self, tmp_path):
        """.openant.md is detected."""
        path = tmp_path / ".openant.md"
        path.write_text("# override")
        result = find_override_file(tmp_path)
        assert result == path

    def test_priority_md_over_json(self, tmp_path):
        """When both OPENANT.md and OPENANT.json exist, MD is preferred."""
        md = tmp_path / "OPENANT.md"
        md.write_text("# md override")
        js = tmp_path / "OPENANT.json"
        js.write_text('{"application_type": "web_app"}')
        result = find_override_file(tmp_path)
        # OPENANT.md is listed first in MANUAL_OVERRIDE_FILES
        assert result == md
        assert MANUAL_OVERRIDE_FILES.index("OPENANT.md") < MANUAL_OVERRIDE_FILES.index("OPENANT.json")

    def test_directory_with_override_name_is_skipped(self, tmp_path):
        """A directory named OPENANT.md must NOT be returned — only regular
        files are valid overrides, matching the Go CLI's behavior. Otherwise
        merge mode would crash trying to read_text() on a directory."""
        d = tmp_path / "OPENANT.md"
        d.mkdir()
        # A real override file lower in priority should be picked up instead.
        json_override = tmp_path / "OPENANT.json"
        json_override.write_text('{"application_type": "web_app"}')

        result = find_override_file(tmp_path)
        assert result == json_override

    def test_directory_only_returns_none(self, tmp_path):
        """If the only matching path is a directory, return None — not crash."""
        (tmp_path / "OPENANT.md").mkdir()
        assert find_override_file(tmp_path) is None

    def test_accepts_str_path(self, tmp_path):
        """Helper accepts a Path; calling with str via Path() conversion works."""
        (tmp_path / "OPENANT.md").write_text("# override")
        result = find_override_file(Path(str(tmp_path)))
        assert result is not None
        assert result.name == "OPENANT.md"


class TestGatherContextSourcesMerge:
    """Tests for `gather_context_sources()` with override_path (merge mode)."""

    def test_no_override_path(self, tmp_path):
        """Without override_path, override file is not included as a source."""
        (tmp_path / "README.md").write_text("# readme")
        sources = gather_context_sources(tmp_path)
        assert "README.md" in sources
        # No OPENANT.md key because we didn't pass override_path
        assert "OPENANT.md" not in sources

    def test_override_path_included(self, tmp_path):
        """When override_path is provided, its content is included."""
        readme = tmp_path / "README.md"
        readme.write_text("# readme")
        override = tmp_path / "OPENANT.md"
        override.write_text("# manual override\nIntended behavior")

        sources = gather_context_sources(tmp_path, override_path=override)
        assert "OPENANT.md" in sources
        assert "manual override" in sources["OPENANT.md"]

    def test_override_truncated_when_huge(self, tmp_path):
        """Override content >10000 chars is truncated."""
        override = tmp_path / "OPENANT.md"
        override.write_text("x" * 12000)
        sources = gather_context_sources(tmp_path, override_path=override)
        content = sources["OPENANT.md"]
        assert "[... truncated ...]" in content
        # 10000 + truncation marker
        assert len(content) < 12000


class TestGenerateApplicationContextDispatch:
    """Tests for the override-mode dispatch inside generate_application_context.

    These avoid hitting the LLM by exercising the "use" path (which returns
    early when an override file is found).
    """

    def _write_valid_override_md(self, repo_path: Path) -> Path:
        """Write a minimal valid OPENANT.md that check_manual_override accepts."""
        # check_manual_override prefers OPENANT.json for structured input;
        # use OPENANT.json with the schema generate_application_context expects.
        path = repo_path / "OPENANT.json"
        path.write_text(
            '{"application_type": "web_app", "purpose": "test app", '
            '"confidence": "high", "intended_behaviors": [], '
            '"trust_boundaries": [], "not_a_vulnerability": []}'
        )
        return path

    def test_use_mode_returns_override_without_llm(self, tmp_path):
        """override_mode='use' with an override file returns it verbatim
        without ever calling the LLM."""
        self._write_valid_override_md(tmp_path)

        # If the LLM is called, this will blow up because we don't patch it.
        # Test passes if we get a context back without any Anthropic call.
        with patch("context.application_context.Anthropic") as mock_anth:
            ctx = generate_application_context(tmp_path, override_mode="use")
            mock_anth.assert_not_called()
        assert ctx.application_type == "web_app"

    def test_force_regenerate_ignores_override(self, tmp_path):
        """force_regenerate=True (legacy) should NOT short-circuit to override."""
        self._write_valid_override_md(tmp_path)

        with patch("context.application_context.Anthropic") as mock_anth:
            # The LLM would be called — we don't actually want to wait for it.
            # We just confirm the early-return for "use" did NOT happen by
            # asserting Anthropic was instantiated. We then bail with an
            # exception inside the mock to avoid running the rest.
            mock_anth.side_effect = RuntimeError("LLM-call-attempted")
            with pytest.raises(RuntimeError, match="LLM-call-attempted"):
                generate_application_context(tmp_path, force_regenerate=True)
            mock_anth.assert_called_once()

    def test_override_mode_ignore_skips_override(self, tmp_path):
        """override_mode='ignore' should NOT short-circuit to override."""
        self._write_valid_override_md(tmp_path)

        with patch("context.application_context.Anthropic") as mock_anth:
            mock_anth.side_effect = RuntimeError("LLM-call-attempted")
            with pytest.raises(RuntimeError, match="LLM-call-attempted"):
                generate_application_context(tmp_path, override_mode="ignore")
            mock_anth.assert_called_once()

    def test_override_mode_merge_includes_supplement(self, tmp_path):
        """override_mode='merge' should send the override content + supplement
        to the LLM."""
        override = tmp_path / "OPENANT.md"
        override.write_text("# manual override\nIntended behavior")
        # Need at least one source so gather_context_sources doesn't raise
        (tmp_path / "README.md").write_text("# readme")

        captured_prompt = {}

        class _FakeContent:
            def __init__(self, text):
                self.text = text

        class _FakeResponse:
            def __init__(self, text):
                self.content = [_FakeContent(text)]

        def _fake_create(**kwargs):
            captured_prompt["content"] = kwargs["messages"][0]["content"]
            return _FakeResponse(
                '```json\n'
                '{"application_type": "web_app", "purpose": "x", '
                '"confidence": "high", "intended_behaviors": [], '
                '"trust_boundaries": [], "not_a_vulnerability": []}\n'
                '```'
            )

        with patch("context.application_context.Anthropic") as mock_anth:
            instance = mock_anth.return_value
            instance.messages.create.side_effect = _fake_create
            ctx = generate_application_context(tmp_path, override_mode="merge")

        assert "OPENANT.md" in captured_prompt["content"]
        assert MERGE_CONTEXT_SUPPLEMENT.strip() in captured_prompt["content"]
        # Source should be marked as 'merged' when an override is merged.
        assert ctx.source == "merged"


class TestPythonCLIArgparse:
    """Verify the argparse-level wiring of --override-mode and --force.

    Invokes the CLI via subprocess to verify the public surface.
    """

    @staticmethod
    def _run_cli(*args):
        import os
        import subprocess
        import sys

        env = os.environ.copy()
        # Don't let the test reach a real LLM
        env.pop("ANTHROPIC_API_KEY", None)
        return subprocess.run(
            [sys.executable, "-m", "openant.cli"] + list(args),
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

    def test_override_mode_choices_validation(self):
        """--override-mode rejects values outside use/ignore/merge."""
        result = self._run_cli(
            "generate-context", "/tmp/nonexistent-repo",
            "--override-mode", "bogus",
        )
        assert result.returncode != 0
        # argparse error mentions invalid choice and the offending value
        assert "invalid choice" in (result.stderr + result.stdout).lower()

    def test_override_mode_help_lists_choices(self):
        """`generate-context --help` advertises the override-mode flag."""
        result = self._run_cli("generate-context", "--help")
        assert result.returncode == 0
        out = result.stdout + result.stderr
        assert "--override-mode" in out
        # All three valid values appear in help text
        assert "use" in out
        assert "merge" in out
        assert "ignore" in out
