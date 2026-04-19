"""Tests for AssistantMessage.error -> sdk_errors mapping in _run_query.

The hot path (_run_query) requires an actual ClaudeSDKClient subprocess, so we
can't unit-test it end-to-end without live API access. What we CAN test is the
error-classification and rate-limiter-notification logic in isolation: mock out
the message stream and assert the right exception propagates and the right
rate-limiter call fires.
"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Each test gets a clean rate-limiter singleton."""
    from utilities import rate_limiter
    rate_limiter._instance = None
    yield
    rate_limiter._instance = None


def _assistant_msg(error=None, text=None):
    """Build a real AssistantMessage — isinstance checks in _run_query need the real class."""
    content = [TextBlock(text=text)] if text else []
    return AssistantMessage(content=content, model="test-model", error=error)


def _result_msg(cost=0.0):
    return ResultMessage(
        subtype="success",
        duration_ms=100,
        duration_api_ms=50,
        is_error=False,
        num_turns=1,
        session_id="test",
        total_cost_usd=cost,
        usage={},
    )


class _FakeClient:
    """Drop-in stand-in for ClaudeSDKClient async context manager."""

    def __init__(self, messages):
        self._messages = messages

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def query(self, prompt):
        return None

    async def receive_response(self):
        for msg in self._messages:
            yield msg


def _run(messages):
    """Invoke _run_query with a scripted message sequence. Returns (result, text) or raises."""
    from utilities.llm_client import _run_query

    options = MagicMock()
    options.model = "test-model"
    options.max_turns = 1

    # _run_query imports ClaudeSDKClient from claude_agent_sdk on each call;
    # patching the source module swaps it in place.
    with patch("claude_agent_sdk.ClaudeSDKClient", lambda options: _FakeClient(messages)):
        return asyncio.run(_run_query("prompt", options))


class TestAssistantMessageErrorMapping:
    def test_rate_limit_raises_rate_limit_error(self):
        from utilities.sdk_errors import RateLimitError
        msgs = [_assistant_msg(error="rate_limit", text="too many")]
        with pytest.raises(RateLimitError):
            _run(msgs)

    def test_rate_limit_notifies_global_limiter(self):
        from utilities.sdk_errors import RateLimitError
        from utilities.rate_limiter import get_rate_limiter

        limiter = get_rate_limiter()
        limiter.report_rate_limit = MagicMock()

        msgs = [_assistant_msg(error="rate_limit", text="slow down")]
        with pytest.raises(RateLimitError):
            _run(msgs)

        limiter.report_rate_limit.assert_called_once_with(0)

    def test_auth_error(self):
        from utilities.sdk_errors import AuthError
        msgs = [_assistant_msg(error="authentication_failed", text="bad key")]
        with pytest.raises(AuthError):
            _run(msgs)

    def test_billing_error(self):
        from utilities.sdk_errors import BillingError
        msgs = [_assistant_msg(error="billing_error")]
        with pytest.raises(BillingError):
            _run(msgs)

    def test_server_error(self):
        from utilities.sdk_errors import ServerError
        msgs = [_assistant_msg(error="server_error")]
        with pytest.raises(ServerError):
            _run(msgs)

    def test_invalid_request(self):
        from utilities.sdk_errors import InvalidRequestError
        msgs = [_assistant_msg(error="invalid_request")]
        with pytest.raises(InvalidRequestError):
            _run(msgs)

    def test_unknown_error_falls_back(self):
        from utilities.sdk_errors import UnknownLLMError
        msgs = [_assistant_msg(error="unknown")]
        with pytest.raises(UnknownLLMError):
            _run(msgs)

    def test_non_rate_limit_does_not_notify_limiter(self):
        from utilities.sdk_errors import AuthError
        from utilities.rate_limiter import get_rate_limiter

        limiter = get_rate_limiter()
        limiter.report_rate_limit = MagicMock()

        msgs = [_assistant_msg(error="authentication_failed")]
        with pytest.raises(AuthError):
            _run(msgs)

        limiter.report_rate_limit.assert_not_called()

    def test_clean_message_does_not_raise(self):
        msgs = [
            _assistant_msg(error=None, text="hello world"),
            _result_msg(cost=0.001),
        ]
        result_msg, text = _run(msgs)
        assert text == "hello world"
        assert result_msg is not None
