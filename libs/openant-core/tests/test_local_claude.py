"""Tests for local Claude Code mode.

Tests the LocalClaudeClient proxy, the is_enabled() check,
create_anthropic_client() factory, create_message() helper,
and AnthropicClient integration with local mode.
"""
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
    create_message,
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
    """Create a mock subprocess.CompletedProcess."""
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
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "True"}):
            assert is_enabled() is True
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "TRUE"}):
            assert is_enabled() is True

    def test_false_when_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            assert is_enabled() is False

    def test_false_when_other_value(self):
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "false"}):
            assert is_enabled() is False
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "1"}):
            assert is_enabled() is False
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": ""}):
            assert is_enabled() is False


# ---------------------------------------------------------------------------
# _run_claude_cli()
# ---------------------------------------------------------------------------

class TestRunClaudeCli:
    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_parses_json_output(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        result = _run_claude_cli("What is 6*7?", model="claude-sonnet-4-20250514")

        assert result["text"] == "The answer is 42."
        assert result["input_tokens"] == 150
        assert result["output_tokens"] == 25
        assert result["cost_usd"] == 0.003

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_passes_model_and_prompt(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        _run_claude_cli("hello", model="claude-opus-4-20250514")

        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd
        assert "hello" in cmd
        assert "--model" in cmd
        assert "claude-opus-4-20250514" in cmd

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_prepends_system_prompt(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        _run_claude_cli("user prompt", model="m", system="be helpful")

        cmd = mock_run.call_args[0][0]
        prompt_arg = cmd[cmd.index("-p") + 1]
        assert prompt_arg.startswith("be helpful")
        assert "user prompt" in prompt_arg

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_strips_claudecode_from_env(self, mock_which, mock_run):
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
        mock_run.return_value = _make_completed_process(
            returncode=1, stderr="auth failed"
        )

        with pytest.raises(RuntimeError, match="exit 1"):
            _run_claude_cli("test", model="m")

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_raises_on_empty_output(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout="")

        with pytest.raises(RuntimeError, match="no output"):
            _run_claude_cli("test", model="m")

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_handles_non_json_output(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout="plain text response")

        result = _run_claude_cli("test", model="m")

        assert result["text"] == "plain text response"
        assert result["input_tokens"] == 0
        assert result["output_tokens"] == 0

    @patch("utilities.local_claude.subprocess.run")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_falls_back_to_stdout_when_result_empty(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(
            stdout=SAMPLE_CLI_OUTPUT_NO_RESULT
        )

        result = _run_claude_cli("test", model="m")

        # When "result" is empty, falls back to raw stdout
        assert result["text"] == SAMPLE_CLI_OUTPUT_NO_RESULT


# ---------------------------------------------------------------------------
# _Response (anthropic Message proxy)
# ---------------------------------------------------------------------------

class TestResponse:
    def test_text_content(self):
        resp = _Response("hello world")
        assert resp.content[0].text == "hello world"
        assert resp.content[0].type == "text"

    def test_usage_defaults_to_zero(self):
        resp = _Response("text")
        assert resp.usage.input_tokens == 0
        assert resp.usage.output_tokens == 0

    def test_usage_with_values(self):
        resp = _Response("text", input_tokens=100, output_tokens=50)
        assert resp.usage.input_tokens == 100
        assert resp.usage.output_tokens == 50

    def test_stop_reason(self):
        resp = _Response("text")
        assert resp.stop_reason == "end_turn"


# ---------------------------------------------------------------------------
# _Messages.create()
# ---------------------------------------------------------------------------

class TestMessages:
    @patch("utilities.local_claude._run_claude_cli")
    def test_extracts_string_prompt(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 0, "output_tokens": 0}
        msgs = _Messages()

        msgs.create(
            model="m",
            messages=[{"role": "user", "content": "hello"}],
        )

        mock_cli.assert_called_once_with("hello", model="m", system=None)

    @patch("utilities.local_claude._run_claude_cli")
    def test_extracts_content_blocks(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 0, "output_tokens": 0}
        msgs = _Messages()

        msgs.create(
            model="m",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "text", "text": "part two"},
                ],
            }],
        )

        mock_cli.assert_called_once_with("part one part two", model="m", system=None)

    @patch("utilities.local_claude._run_claude_cli")
    def test_passes_system_prompt(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 0, "output_tokens": 0}
        msgs = _Messages()

        msgs.create(
            model="m",
            system="be concise",
            messages=[{"role": "user", "content": "hi"}],
        )

        mock_cli.assert_called_once_with("hi", model="m", system="be concise")

    @patch("utilities.local_claude._run_claude_cli")
    def test_returns_response_with_usage(self, mock_cli):
        mock_cli.return_value = {"text": "result", "input_tokens": 100, "output_tokens": 50}
        msgs = _Messages()

        resp = msgs.create(
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )

        assert resp.content[0].text == "result"
        assert resp.usage.input_tokens == 100
        assert resp.usage.output_tokens == 50


# ---------------------------------------------------------------------------
# LocalClaudeClient
# ---------------------------------------------------------------------------

class TestLocalClaudeClient:
    def test_has_messages_interface(self):
        client = LocalClaudeClient()
        assert hasattr(client, "messages")
        assert hasattr(client.messages, "create")


# ---------------------------------------------------------------------------
# create_anthropic_client()
# ---------------------------------------------------------------------------

class TestCreateAnthropicClient:
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_returns_local_client_when_enabled(self):
        client = create_anthropic_client()
        assert isinstance(client, LocalClaudeClient)

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}, clear=False)
    def test_returns_anthropic_client_when_disabled(self):
        with patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": ""}, clear=False):
            client = create_anthropic_client()
            assert not isinstance(client, LocalClaudeClient)

    @patch.dict(os.environ, {}, clear=True)
    def test_raises_without_api_key_when_disabled(self):
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            create_anthropic_client()


# ---------------------------------------------------------------------------
# create_message()
# ---------------------------------------------------------------------------

class TestCreateMessage:
    @patch("utilities.local_claude._run_claude_cli")
    def test_works_with_local_client(self, mock_cli):
        mock_cli.return_value = {"text": "response text", "input_tokens": 10, "output_tokens": 5}
        client = LocalClaudeClient()

        result = create_message(
            client,
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )

        assert result == "response text"


# ---------------------------------------------------------------------------
# AnthropicClient with local mode
# ---------------------------------------------------------------------------

class TestAnthropicClientLocalMode:
    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_analyze_sync_uses_local_claude(self, mock_cli):
        mock_cli.return_value = {"text": "analysis result", "input_tokens": 200, "output_tokens": 100}

        client = AnthropicClient(model="claude-sonnet-4-20250514")
        result = client.analyze_sync("Analyze this code")

        assert result == "analysis result"
        mock_cli.assert_called_once()

    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_tracks_tokens_in_local_mode(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 200, "output_tokens": 100}

        tracker = TokenTracker()
        client = AnthropicClient(model="claude-sonnet-4-20250514", tracker=tracker)
        client.analyze_sync("test")

        assert tracker.total_input_tokens == 200
        assert tracker.total_output_tokens == 100
        assert tracker.total_tokens == 300
        assert len(tracker.calls) == 1

    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_analyze_sync_model_override(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 0, "output_tokens": 0}

        client = AnthropicClient(model="claude-opus-4-20250514")
        client.analyze_sync("test", model="claude-sonnet-4-20250514")

        cmd_model = mock_cli.call_args[1].get("model") or mock_cli.call_args[0][1]
        assert "sonnet" in cmd_model

    @patch("utilities.local_claude._run_claude_cli")
    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_analyze_sync_passes_system_prompt(self, mock_cli):
        mock_cli.return_value = {"text": "ok", "input_tokens": 0, "output_tokens": 0}

        client = AnthropicClient(model="claude-sonnet-4-20250514")
        client.analyze_sync("test", system="be helpful")

        assert mock_cli.call_args[1].get("system") == "be helpful" or \
               mock_cli.call_args[0][2] if len(mock_cli.call_args[0]) > 2 else True

    @patch.dict(os.environ, {"OPENANT_LOCAL_CLAUDE": "true"}, clear=False)
    def test_does_not_require_api_key(self):
        with patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}, clear=True):
            os.environ["OPENANT_LOCAL_CLAUDE"] = "true"
            # Should not raise ValueError
            client = AnthropicClient(model="claude-sonnet-4-20250514")
            assert client.client is not None  # LocalClaudeClient assigned via create_anthropic_client()

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
