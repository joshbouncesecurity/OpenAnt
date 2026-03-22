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
    _build_tool_system_prompt,
    _serialize_messages,
    _parse_tool_calls,
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

# --- Sample tool definitions for testing ---

SAMPLE_TOOLS = [
    {
        "name": "search_usages",
        "description": "Search for function usages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "finish",
        "description": "Complete the analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "confidence": {
                    "type": "number",
                    "description": "Confidence level"
                }
            },
            "required": ["confidence"]
        }
    },
]


def _make_completed_process(stdout="", stderr="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _make_cli_output(text, input_tokens=100, output_tokens=50):
    """Helper to create CLI JSON output with custom text."""
    return json.dumps({
        "type": "result",
        "subtype": "success",
        "result": text,
        "total_cost_usd": 0.001,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    })


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
    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_parses_json_output_with_usage(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        result = _run_claude_cli("What is 6*7?", model="claude-sonnet-4-20250514")

        assert result["text"] == "The answer is 42."
        assert result["input_tokens"] == 150
        assert result["output_tokens"] == 25
        assert result["cost_usd"] == 0.003

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_passes_prompt_via_stdin(self, mock_which, mock_run):
        """Prompt must be passed via stdin, not as a CLI arg (WinError 206 fix)."""
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        _run_claude_cli("my prompt text", model="m")

        cmd = mock_run.call_args[0][0]
        # -p flag should be present but prompt text should NOT be in the command
        assert "-p" in cmd
        assert "my prompt text" not in cmd
        # Prompt should be passed via input kwarg (stdin)
        assert mock_run.call_args[1]["input"] == "my prompt text"

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_stdin_prompt_with_system(self, mock_which, mock_run):
        """System prompt is prepended and passed via stdin together."""
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)

        _run_claude_cli("user prompt", model="m", system="system instructions")

        assert mock_run.call_args[1]["input"] == "system instructions\n\nuser prompt"

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_large_prompt_via_stdin(self, mock_which, mock_run):
        """Prompts exceeding Windows cmd limit work via stdin."""
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT)
        large_prompt = "x" * 10000  # Exceeds Windows 8191 char limit

        _run_claude_cli(large_prompt, model="m")

        cmd = mock_run.call_args[0][0]
        assert large_prompt not in cmd
        assert mock_run.call_args[1]["input"] == large_prompt

    @patch("utilities.local_claude.run_utf8")
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

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_raises_on_nonzero_exit(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="auth failed")

        with pytest.raises(RuntimeError, match="exit 1"):
            _run_claude_cli("test", model="m")

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_handles_non_json_output(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout="plain text response")

        result = _run_claude_cli("test", model="m")

        assert result["text"] == "plain text response"
        assert result["input_tokens"] == 0

    @patch("utilities.local_claude.run_utf8")
    @patch("utilities.local_claude.shutil.which", return_value="/usr/bin/claude")
    def test_falls_back_to_stdout_when_result_empty(self, mock_which, mock_run):
        mock_run.return_value = _make_completed_process(stdout=SAMPLE_CLI_OUTPUT_NO_RESULT)

        result = _run_claude_cli("test", model="m")

        # When "result" is empty string, falls back to raw stdout
        assert result["text"] == SAMPLE_CLI_OUTPUT_NO_RESULT


# ---------------------------------------------------------------------------
# _parse_tool_calls()
# ---------------------------------------------------------------------------

class TestParseToolCalls:
    def test_single_tool_call(self):
        text = 'Some reasoning\n<tool_call>{"name": "search_usages", "input": {"function_name": "foo"}}</tool_call>'
        blocks, remaining = _parse_tool_calls(text)

        assert len(blocks) == 1
        assert blocks[0].type == "tool_use"
        assert blocks[0].name == "search_usages"
        assert blocks[0].input == {"function_name": "foo"}
        assert blocks[0].id.startswith("toolu_")
        assert remaining == "Some reasoning"

    def test_multiple_tool_calls(self):
        text = (
            '<tool_call>{"name": "search_usages", "input": {"function_name": "a"}}</tool_call>\n'
            '<tool_call>{"name": "read_function", "input": {"function_id": "b"}}</tool_call>'
        )
        blocks, remaining = _parse_tool_calls(text)

        assert len(blocks) == 2
        assert blocks[0].name == "search_usages"
        assert blocks[1].name == "read_function"
        # Each gets a unique ID
        assert blocks[0].id != blocks[1].id

    def test_no_tool_calls(self):
        text = "Just some plain text with no tools."
        blocks, remaining = _parse_tool_calls(text)

        assert len(blocks) == 0
        assert remaining == text

    def test_malformed_json_skipped(self, capsys):
        text = '<tool_call>not valid json</tool_call>\n<tool_call>{"name": "finish", "input": {}}</tool_call>'
        blocks, remaining = _parse_tool_calls(text)

        assert len(blocks) == 1
        assert blocks[0].name == "finish"
        # Warning printed to stderr
        captured = capsys.readouterr()
        assert "malformed tool_call" in captured.err

    def test_multiline_tool_call(self):
        text = '<tool_call>\n{\n  "name": "finish",\n  "input": {"confidence": 0.9}\n}\n</tool_call>'
        blocks, remaining = _parse_tool_calls(text)

        assert len(blocks) == 1
        assert blocks[0].name == "finish"
        assert blocks[0].input == {"confidence": 0.9}


# ---------------------------------------------------------------------------
# _build_tool_system_prompt()
# ---------------------------------------------------------------------------

class TestBuildToolSystemPrompt:
    def test_includes_original_system(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS, "You are a security analyst.")
        assert "You are a security analyst." in result

    def test_includes_tool_names(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS)
        assert "search_usages" in result
        assert "finish" in result

    def test_includes_format_instructions(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS)
        assert "<tool_call>" in result
        assert "tool_name" in result

    def test_includes_parameter_details(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS)
        assert "function_name" in result
        assert "(required)" in result

    def test_no_original_system(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS, None)
        # Should still work, just no original system text
        assert "search_usages" in result

    def test_includes_tool_descriptions(self):
        result = _build_tool_system_prompt(SAMPLE_TOOLS)
        assert "Search for function usages." in result
        assert "Complete the analysis." in result


# ---------------------------------------------------------------------------
# _serialize_messages()
# ---------------------------------------------------------------------------

class TestSerializeMessages:
    def test_string_content(self):
        messages = [{"role": "user", "content": "Analyze this code"}]
        result = _serialize_messages(messages)
        assert "Analyze this code" in result

    def test_text_block_content(self):
        messages = [{"role": "user", "content": [{"type": "text", "text": "Hello world"}]}]
        result = _serialize_messages(messages)
        assert "Hello world" in result

    def test_tool_result_blocks(self):
        messages = [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "abc123", "content": '{"found": true}'}
        ]}]
        result = _serialize_messages(messages)
        assert "Tool result (id: abc123)" in result
        assert '{"found": true}' in result

    def test_attribute_based_tool_use_blocks(self):
        """Test serialization of response.content objects (attribute-based)."""
        tool_block = type("ToolUseBlock", (), {
            "type": "tool_use",
            "name": "search_usages",
            "input": {"function_name": "foo"},
            "id": "toolu_123",
        })()
        text_block = type("TextBlock", (), {
            "type": "text",
            "text": "Let me search for that.",
        })()

        messages = [{"role": "assistant", "content": [text_block, tool_block]}]
        result = _serialize_messages(messages)
        assert "Let me search for that." in result
        assert "I called search_usages with:" in result
        assert '"function_name": "foo"' in result

    def test_multi_turn_conversation(self):
        """Test full multi-turn message serialization."""
        tool_block = type("ToolUseBlock", (), {
            "type": "tool_use",
            "name": "search_usages",
            "input": {"function_name": "validate"},
            "id": "toolu_abc",
        })()

        messages = [
            {"role": "user", "content": "Analyze function X"},
            {"role": "assistant", "content": [tool_block]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_abc", "content": "found 3 usages"}
            ]},
        ]
        result = _serialize_messages(messages)
        assert "Analyze function X" in result
        assert "I called search_usages" in result
        assert "Tool result (id: toolu_abc)" in result
        assert "found 3 usages" in result


# ---------------------------------------------------------------------------
# _Messages.create() with tools
# ---------------------------------------------------------------------------

class TestMessagesCreateWithTools:
    @patch("utilities.local_claude._run_claude_cli")
    def test_returns_tool_use_blocks(self, mock_cli):
        mock_cli.return_value = {
            "text": 'Thinking...\n<tool_call>{"name": "search_usages", "input": {"function_name": "foo"}}</tool_call>',
            "input_tokens": 100,
            "output_tokens": 50,
            "cost_usd": 0.001,
        }

        msgs = _Messages()
        response = msgs.create(
            model="claude-sonnet-4-20250514",
            system="You are a security analyst.",
            tools=SAMPLE_TOOLS,
            messages=[{"role": "user", "content": "Analyze this"}],
        )

        # Should have text block + tool_use block
        assert len(response.content) == 2
        assert response.content[0].type == "text"
        assert "Thinking" in response.content[0].text
        assert response.content[1].type == "tool_use"
        assert response.content[1].name == "search_usages"
        assert response.content[1].input == {"function_name": "foo"}
        assert response.content[1].id.startswith("toolu_")

    @patch("utilities.local_claude._run_claude_cli")
    def test_stop_reason_tool_use(self, mock_cli):
        mock_cli.return_value = {
            "text": '<tool_call>{"name": "finish", "input": {"confidence": 0.8}}</tool_call>',
            "input_tokens": 100,
            "output_tokens": 50,
            "cost_usd": 0.001,
        }

        msgs = _Messages()
        response = msgs.create(
            tools=SAMPLE_TOOLS,
            messages=[{"role": "user", "content": "test"}],
        )

        assert response.stop_reason == "tool_use"

    @patch("utilities.local_claude._run_claude_cli")
    def test_stop_reason_end_turn_no_tools(self, mock_cli):
        mock_cli.return_value = {
            "text": "Just plain text, no tool calls.",
            "input_tokens": 100,
            "output_tokens": 50,
            "cost_usd": 0.001,
        }

        msgs = _Messages()
        response = msgs.create(
            tools=SAMPLE_TOOLS,
            messages=[{"role": "user", "content": "test"}],
        )

        assert response.stop_reason == "end_turn"

    @patch("utilities.local_claude._run_claude_cli")
    def test_usage_tracked(self, mock_cli):
        mock_cli.return_value = {
            "text": '<tool_call>{"name": "finish", "input": {}}</tool_call>',
            "input_tokens": 200,
            "output_tokens": 75,
            "cost_usd": 0.002,
        }

        msgs = _Messages()
        response = msgs.create(
            tools=SAMPLE_TOOLS,
            messages=[{"role": "user", "content": "test"}],
        )

        assert response.usage.input_tokens == 200
        assert response.usage.output_tokens == 75

    @patch("utilities.local_claude._run_claude_cli")
    def test_system_prompt_includes_tools(self, mock_cli):
        mock_cli.return_value = {
            "text": "no tools",
            "input_tokens": 10,
            "output_tokens": 5,
            "cost_usd": 0.0,
        }

        msgs = _Messages()
        msgs.create(
            system="Base system prompt",
            tools=SAMPLE_TOOLS,
            messages=[{"role": "user", "content": "test"}],
        )

        # Check that _run_claude_cli was called with enhanced system prompt
        call_kwargs = mock_cli.call_args
        system_arg = call_kwargs[1]["system"] if "system" in call_kwargs[1] else call_kwargs[0][2] if len(call_kwargs[0]) > 2 else None
        # The system prompt is passed as kwarg 'system' to _run_claude_cli
        _, kwargs = mock_cli.call_args
        assert "search_usages" in kwargs["system"]
        assert "Base system prompt" in kwargs["system"]


class TestMessagesCreateWithoutTools:
    """Backwards compatibility — create() without tools still works."""

    @patch("utilities.local_claude._run_claude_cli")
    def test_text_only_path(self, mock_cli):
        mock_cli.return_value = {
            "text": "The answer is 42.",
            "input_tokens": 100,
            "output_tokens": 20,
            "cost_usd": 0.001,
        }

        msgs = _Messages()
        response = msgs.create(
            model="claude-sonnet-4-20250514",
            messages=[{"role": "user", "content": "What is 6*7?"}],
        )

        assert response.content[0].type == "text"
        assert response.content[0].text == "The answer is 42."
        assert response.stop_reason == "end_turn"
        assert response.usage.input_tokens == 100


# ---------------------------------------------------------------------------
# _Response backwards compatibility
# ---------------------------------------------------------------------------

class TestResponse:
    def test_text_positional_arg(self):
        """Existing callers pass text as positional arg."""
        resp = _Response("hello")
        assert resp.content[0].type == "text"
        assert resp.content[0].text == "hello"
        assert resp.stop_reason == "end_turn"

    def test_content_kwarg(self):
        """New path passes content list directly."""
        block = type("ToolUseBlock", (), {"type": "tool_use", "name": "x", "input": {}, "id": "1"})()
        resp = _Response(content=[block], stop_reason="tool_use")
        assert resp.content[0].type == "tool_use"
        assert resp.stop_reason == "tool_use"

    def test_usage_present(self):
        resp = _Response("hi", input_tokens=10, output_tokens=5)
        assert resp.usage.input_tokens == 10
        assert resp.usage.output_tokens == 5


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
