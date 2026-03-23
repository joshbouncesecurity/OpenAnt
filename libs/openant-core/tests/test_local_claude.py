"""Tests for SDK-backed LLM client."""
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from utilities.llm_client import (
    _build_env,
    _build_options,
    _run_query_sync,
    run_native_verification,
    AnthropicClient,
    TokenTracker,
)


# ---------------------------------------------------------------------------
# Helpers to build mock SDK messages
# ---------------------------------------------------------------------------

def _make_result_message(
    result="The answer is 42.",
    input_tokens=150,
    output_tokens=25,
    cost=0.003,
    structured_output=None,
):
    """Create a mock ResultMessage matching the SDK's interface."""
    msg = MagicMock()
    msg.result = result
    msg.usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    msg.total_cost_usd = cost
    msg.structured_output = structured_output
    return msg


# ---------------------------------------------------------------------------
# _build_env()
# ---------------------------------------------------------------------------

class TestBuildEnv:
    def test_includes_api_key_when_set(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test", "OPENANT_LOCAL_CLAUDE": ""}, clear=False):
            env = _build_env()
            assert env["ANTHROPIC_API_KEY"] == "sk-test"

    def test_no_api_key_in_local_mode(self):
        """Local mode should not pass API key even if set."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test", "OPENANT_LOCAL_CLAUDE": "true"}, clear=False):
            env = _build_env()
            assert "ANTHROPIC_API_KEY" not in env

    def test_no_api_key_when_not_set(self):
        env_without_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            env = _build_env()
            assert "ANTHROPIC_API_KEY" not in env

    def test_includes_config_dir_when_set(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/home/.claude-k"}, clear=False):
            env = _build_env()
            assert env["CLAUDE_CONFIG_DIR"] == "/home/.claude-k"

    def test_clears_claudecode(self):
        with patch.dict(os.environ, {"CLAUDECODE": "1"}, clear=False):
            env = _build_env()
            assert env["CLAUDECODE"] == ""


# ---------------------------------------------------------------------------
# _build_options()
# ---------------------------------------------------------------------------

class TestBuildOptions:
    def test_sets_model(self):
        opts = _build_options("claude-opus-4-6")
        assert opts.model == "claude-opus-4-6"

    def test_sets_system_prompt(self):
        opts = _build_options("m", system="You are a security analyst.")
        assert opts.system_prompt == "You are a security analyst."

    def test_sets_max_turns(self):
        opts = _build_options("m", max_turns=5)
        assert opts.max_turns == 5

    def test_sets_allowed_tools(self):
        opts = _build_options("m", allowed_tools=["Read", "Grep"])
        assert opts.allowed_tools == ["Read", "Grep"]

    def test_default_allowed_tools_empty(self):
        opts = _build_options("m")
        assert opts.allowed_tools == []

    def test_sets_permission_mode(self):
        opts = _build_options("m")
        assert opts.permission_mode == "bypassPermissions"

    def test_passes_extra_kwargs(self):
        opts = _build_options("m", add_dirs=["/tmp/repo"], max_budget_usd=1.0)
        assert opts.add_dirs == ["/tmp/repo"]
        assert opts.max_budget_usd == 1.0


# ---------------------------------------------------------------------------
# AnthropicClient — token tracking
# ---------------------------------------------------------------------------

class TestAnthropicClientTokenTracking:
    @patch("utilities.llm_client._run_query_sync")
    def test_tracks_tokens(self, mock_query):
        mock_query.return_value = (
            _make_result_message(result="ok", input_tokens=200, output_tokens=100, cost=0.01),
            "ok",
        )

        tracker = TokenTracker()
        client = AnthropicClient(model="claude-sonnet-4-6", tracker=tracker)
        result = client.analyze_sync("test")

        assert result == "ok"
        assert tracker.total_input_tokens == 200
        assert tracker.total_output_tokens == 100
        assert tracker.total_cost_usd == 0.01
        assert len(tracker.calls) == 1

    @patch("utilities.llm_client._run_query_sync")
    def test_tracks_sdk_cost(self, mock_query):
        """Uses SDK-reported cost, not pricing table estimate."""
        mock_query.return_value = (
            _make_result_message(result="ok", input_tokens=100, output_tokens=50, cost=0.0042),
            "ok",
        )

        tracker = TokenTracker()
        client = AnthropicClient(model="claude-sonnet-4-6", tracker=tracker)
        client.analyze_sync("test")

        assert tracker.total_cost_usd == 0.0042

    @patch("utilities.llm_client._run_query_sync")
    def test_last_call_populated(self, mock_query):
        mock_query.return_value = (
            _make_result_message(result="ok", input_tokens=50, output_tokens=20, cost=0.001),
            "ok",
        )

        client = AnthropicClient(model="claude-sonnet-4-6")
        client.analyze_sync("test")

        last = client.get_last_call()
        assert last is not None
        assert last["input_tokens"] == 50
        assert last["output_tokens"] == 20

    @patch("utilities.llm_client._run_query_sync")
    def test_falls_back_to_assistant_text(self, mock_query):
        """When ResultMessage.result is None, use last AssistantMessage text."""
        mock_query.return_value = (
            _make_result_message(result=None),
            "Fallback text",
        )

        client = AnthropicClient(model="claude-sonnet-4-6")
        result = client.analyze_sync("test")

        assert result == "Fallback text"


# ---------------------------------------------------------------------------
# run_native_verification() — SDK-backed
# ---------------------------------------------------------------------------

class TestRunNativeVerification:
    @patch("utilities.llm_client._run_query_sync")
    def test_returns_result_text(self, mock_query):
        mock_query.return_value = (
            _make_result_message(
                result='{"agree": false, "correct_finding": "safe"}',
                input_tokens=5000,
                output_tokens=2000,
                cost=1.25,
            ),
            "",
        )

        result = run_native_verification(
            prompt="Verify this", system="sys", model="claude-opus-4-6",
            repo_path="/tmp/repo",
        )

        assert result["text"] == '{"agree": false, "correct_finding": "safe"}'
        assert result["input_tokens"] == 5000
        assert result["output_tokens"] == 2000
        assert result["cost_usd"] == 1.25

    @patch("utilities.llm_client._run_query_sync")
    def test_uses_structured_output_when_available(self, mock_query):
        structured = {"agree": False, "correct_finding": "safe", "explanation": "sanitized"}
        mock_query.return_value = (
            _make_result_message(
                result="some text",
                structured_output=structured,
            ),
            "",
        )

        result = run_native_verification(
            prompt="test", system="sys", model="m", repo_path="/tmp/repo",
            json_schema={"type": "object"},
        )

        assert json.loads(result["text"]) == structured

    @patch("utilities.llm_client._run_query_sync")
    def test_passes_correct_options(self, mock_query):
        mock_query.return_value = (_make_result_message(), "")

        run_native_verification(
            prompt="Verify this finding",
            system="You are a pentester.",
            model="claude-opus-4-6",
            repo_path="/tmp/target-repo",
            max_budget_usd=5.0,
        )

        prompt, options = mock_query.call_args[0]
        assert prompt == "Verify this finding"
        assert options.model == "claude-opus-4-6"
        assert options.system_prompt == "You are a pentester."
        assert options.max_turns is None  # Multi-turn
        assert "Read" in options.allowed_tools
        assert "Grep" in options.allowed_tools
        assert options.max_budget_usd == 5.0
        assert options.permission_mode == "bypassPermissions"

    @patch("utilities.llm_client._run_query_sync")
    def test_sets_output_format_with_json_schema(self, mock_query):
        mock_query.return_value = (_make_result_message(), "")
        schema = {"type": "object", "properties": {"agree": {"type": "boolean"}}}

        run_native_verification(
            prompt="test", system="sys", model="m", repo_path="/tmp/repo",
            json_schema=schema,
        )

        options = mock_query.call_args[0][1]
        assert options.output_format == {"type": "json_schema", "schema": schema}

    @patch("utilities.llm_client._run_query_sync")
    def test_no_output_format_without_schema(self, mock_query):
        mock_query.return_value = (_make_result_message(), "")

        run_native_verification(
            prompt="test", system="sys", model="m", repo_path="/tmp/repo",
        )

        options = mock_query.call_args[0][1]
        assert options.output_format is None

    @patch("utilities.llm_client._run_query_sync")
    def test_raises_when_no_result_message(self, mock_query):
        mock_query.return_value = (None, "some text")

        with pytest.raises(RuntimeError, match="no ResultMessage"):
            run_native_verification(
                prompt="test", system="sys", model="m", repo_path="/tmp/repo",
            )

    @patch("utilities.llm_client._run_query_sync")
    def test_falls_back_to_last_text_when_result_none(self, mock_query):
        mock_query.return_value = (
            _make_result_message(result=None),
            "fallback text from assistant",
        )

        result = run_native_verification(
            prompt="test", system="sys", model="m", repo_path="/tmp/repo",
        )

        assert result["text"] == "fallback text from assistant"


# ---------------------------------------------------------------------------
# FindingVerifier with SDK-backed verification
# ---------------------------------------------------------------------------

class TestVerifyWithNativeClaude:
    """Tests for native Claude Code verification path in FindingVerifier."""

    def _make_verifier(self, repo_path="/tmp/repo"):
        from utilities.finding_verifier import FindingVerifier

        index = MagicMock()
        index.repo_path = Path(repo_path) if repo_path else None
        tracker = TokenTracker()
        verifier = FindingVerifier(index=index, tracker=tracker)
        return verifier, tracker

    @patch("utilities.llm_client._run_query_sync")
    def test_routes_to_native_verification(self, mock_query):
        verdict = {
            "agree": False,
            "correct_finding": "safe",
            "explanation": "The input is sanitized.",
            "exploit_path": {
                "entry_point": "POST /api/upload",
                "data_flow": ["req.body.filename", "sanitize(filename)"],
                "sink_reached": False,
                "attacker_control_at_sink": "none",
                "path_broken_at": "sanitize()",
            },
        }
        mock_query.return_value = (
            _make_result_message(
                result=json.dumps(verdict),
                input_tokens=5000,
                output_tokens=2000,
                cost=1.25,
            ),
            "",
        )

        verifier, tracker = self._make_verifier()
        result = verifier.verify_result(
            code="function upload(req) { fs.writeFile(req.body.name, data); }",
            finding="vulnerable",
            attack_vector="path traversal via filename",
            reasoning="unsanitized filename in writeFile",
        )

        assert result.correct_finding == "safe"
        assert result.agree is False
        assert tracker.total_cost_usd == 1.25

    def test_fallback_when_no_repo_path(self):
        verifier, _ = self._make_verifier(repo_path=None)
        result = verifier.verify_result(
            code="code", finding="vulnerable",
            attack_vector="test", reasoning="test",
        )

        assert result.agree is True
        assert result.correct_finding == "vulnerable"
        assert "No repo_path" in result.explanation

    @patch("utilities.llm_client._run_query_sync")
    def test_sdk_failure_returns_fallback(self, mock_query):
        mock_query.side_effect = RuntimeError("SDK crashed")

        verifier, _ = self._make_verifier()
        result = verifier.verify_result(
            code="code", finding="bypassable",
            attack_vector="test", reasoning="test",
        )

        assert result.agree is True
        assert result.correct_finding == "bypassable"

    @patch("utilities.llm_client._run_query_sync")
    def test_parses_json_from_code_block(self, mock_query):
        verdict_json = json.dumps({
            "agree": False,
            "correct_finding": "protected",
            "explanation": "Auth check prevents exploitation.",
        })
        mock_query.return_value = (
            _make_result_message(
                result=f"Here's my analysis:\n\n```json\n{verdict_json}\n```",
            ),
            "",
        )

        verifier, _ = self._make_verifier()
        result = verifier.verify_result(
            code="code", finding="vulnerable",
            attack_vector="test", reasoning="test",
        )

        assert result.correct_finding == "protected"
        assert result.agree is False

    @patch("utilities.llm_client._run_query_sync")
    def test_unparseable_response_returns_fallback(self, mock_query):
        mock_query.return_value = (
            _make_result_message(result="not json at all"),
            "",
        )

        verifier, _ = self._make_verifier()
        result = verifier.verify_result(
            code="code", finding="vulnerable",
            attack_vector="test", reasoning="test",
        )

        assert result.agree is True
        assert result.correct_finding == "vulnerable"


# ---------------------------------------------------------------------------
# TokenTracker
# ---------------------------------------------------------------------------

class TestTokenTrackerRestoreFrom:
    def test_restore_from_checkpoint(self):
        tracker = TokenTracker()
        tracker.restore_from({
            "total_input_tokens": 1000,
            "total_output_tokens": 500,
            "total_cost_usd": 0.05,
        })

        assert tracker.total_input_tokens == 1000
        assert tracker.total_output_tokens == 500
        assert tracker.total_cost_usd == 0.05

    def test_restore_then_record_accumulates(self):
        tracker = TokenTracker()
        tracker.restore_from({
            "total_input_tokens": 1000,
            "total_output_tokens": 500,
            "total_cost_usd": 0.05,
        })
        tracker.record_call("claude-sonnet-4-6", 200, 100, cost_usd=0.01)

        assert tracker.total_input_tokens == 1200
        assert tracker.total_output_tokens == 600
        assert abs(tracker.total_cost_usd - 0.06) < 1e-9
