"""Tests for local Claude Code mode."""
import json
import os
from unittest.mock import patch, MagicMock

import pytest

from utilities.local_claude import (
    is_enabled,
    _run_claude_cli,
    _Response,
    _Messages,
    LocalClaudeClient,
)
from utilities.llm_client import (
    AnthropicClient,
    TokenTracker,
    create_anthropic_client,
)


# --- Sample CLI JSON output matching real `claude -p --output-format json` ---

SAMPLE_CLI_OUTPUT = json.dumps({
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "result": "The answer is 42.",
    "duration_ms": 1500,
    "num_turns": 1,
    "stop_reason": "end_turn",
    "total_cost_usd": 0.003,
    "usage": {
        "input_tokens": 150,
        "output_tokens": 25,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    },
})

SAMPLE_CLI_OUTPUT_NO_RESULT = json.dumps({
    "type": "result",
    "subtype": "success",
    "result": "",
    "total_cost_usd": 0.0,
    "usage": {"input_tokens": 0, "output_tokens": 0},
})


def _make_completed_process(stdout="", stderr="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


# ---------------------------------------------------------------------------
# is_enabled()
# ---------------------------------------------------------------------------

class TestIsEnabled:
    def test_true_when_set(self):
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}):
            assert is_enabled() is True

    def test_true_case_insensitive(self):
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "TRUE"}):
            assert is_enabled() is True

    def test_false_when_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            assert is_enabled() is False

    def test_false_for_other_values(self):
        for val in ("false", "1", "yes", ""):
            with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": val}):
                assert is_enabled() is False, f"Expected False for {val!r}"


# ---------------------------------------------------------------------------
# _run_claude_cli()
# ---------------------------------------------------------------------------

class TestRunClaudeCli:
    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_parses_json_output_with_usage(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        result = _run_claude_cli("What is 6*7?", model="claude-sonnet-4-20250514")

        assert result["text"] == "The answer is 42."
        assert result["input_tokens"] == 150
        assert result["output_tokens"] == 25
        assert result["cost_usd"] == 0.003

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_strips_claudecode_from_env(self, mock_which, mock_run):
        """Prevents 'nested session' error when run from within Claude Code."""
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        with patch.dict(os.environ, {"CLAUDECODE": "1", "PATH": "/usr/bin"}):
            _run_claude_cli("test", model="m")

        env = mock_run.call_args[1]["env"]
        assert "CLAUDECODE" not in env
        assert "PATH" in env

    @patch("utilities.local_claude.shutil.which", return_value=None)
    def test_raises_when_claude_not_found(self, mock_which):
        with pytest.raises(FileNotFoundError, match="claude CLI not found"):
            _run_claude_cli("test", model="m")

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_raises_on_nonzero_exit(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="auth failed")

        with pytest.raises(RuntimeError, match="exit 1"):
            _run_claude_cli("test", model="m")

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_handles_non_json_output(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout="plain text response")

        result = _run_claude_cli("test", model="m")

        assert result["text"] == "plain text response"
        assert result["input_tokens"] == 0

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_falls_back_to_stdout_when_result_empty(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT_NO_RESULT)

        result = _run_claude_cli("test", model="m")

        # When "result" is empty string, falls back to raw stdout
        assert result["text"] == SAMPLE_CLI_OUTPUT_NO_RESULT


# ---------------------------------------------------------------------------
# create_anthropic_client()
# ---------------------------------------------------------------------------

class TestCreateAnthropicClient:
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_returns_local_client_when_enabled(self):
        client = create_anthropic_client()
        assert isinstance(client, LocalClaudeClient)

    @patch.dict(os.environ, {}, clear=True)
    def test_raises_without_api_key_when_disabled(self):
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            create_anthropic_client()


# ---------------------------------------------------------------------------
# AnthropicClient with local mode — token tracking end-to-end
# ---------------------------------------------------------------------------

class TestAnthropicClientLocalMode:
    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_tracks_tokens_in_local_mode(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 200, "output_tokens": 100}

        tracker = TokenTracker()
        client = AnthropicClient(model="claude-sonnet-4-20250514", tracker=tracker)
        result = client.analyze_sync("test")

        assert result == "ok"
        assert tracker.total_input_tokens == 200
        assert tracker.total_output_tokens == 100
        assert len(tracker.calls) == 1
        assert tracker.calls[0]["model"] == "claude-sonnet-4-20250514"

    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_does_not_require_api_key(self):
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        env["OPENANT_LOCAL_CLAUDE"] = "true"
        with patch.dict(os.environ, env, clear=True):
            # Should not raise ValueError
            client = AnthropicClient(model="claude-sonnet-4-20250514")
            assert client.client is not None

    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_last_call_populated(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 50, "output_tokens": 20}

        client = AnthropicClient(model="claude-sonnet-4-20250514")
        client.analyze_sync("test")

        last = client.get_last_call()
        assert last is not None
        assert last["input_tokens"] == 50
        assert last["output_tokens"] == 20
        assert last["model"] == "claude-sonnet-4-20250514"
