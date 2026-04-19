"""Tests for utilities.sdk_errors."""
import pytest

from utilities.sdk_errors import (
    OpenAntLLMError,
    AuthError,
    BillingError,
    RateLimitError,
    InvalidRequestError,
    ServerError,
    UnknownLLMError,
    error_from_kind,
    classify_error,
)


class TestErrorFromKind:
    def test_each_known_kind_maps_to_correct_class(self):
        cases = [
            ("authentication_failed", AuthError),
            ("billing_error", BillingError),
            ("rate_limit", RateLimitError),
            ("invalid_request", InvalidRequestError),
            ("server_error", ServerError),
            ("unknown", UnknownLLMError),
        ]
        for kind, expected_cls in cases:
            exc = error_from_kind(kind)
            assert isinstance(exc, expected_cls), f"{kind} -> {type(exc).__name__}"
            assert exc.error_kind == kind

    def test_unrecognized_kind_falls_back_to_unknown(self):
        exc = error_from_kind("not_a_real_kind")
        assert isinstance(exc, UnknownLLMError)

    def test_custom_message_used_when_provided(self):
        exc = error_from_kind("rate_limit", "hit the limit")
        assert "hit the limit" in str(exc)

    def test_default_message_mentions_kind(self):
        exc = error_from_kind("server_error")
        assert "server_error" in str(exc)


class TestClassifyError:
    def test_rate_limit(self):
        info = classify_error(RateLimitError("rate limit hit"))
        assert info["type"] == "rate_limit"
        assert info["exception_class"] == "RateLimitError"
        assert "rate limit hit" in info["message"]

    def test_auth_billing_server_invalid_request(self):
        assert classify_error(AuthError())["type"] == "auth"
        assert classify_error(BillingError())["type"] == "billing"
        assert classify_error(ServerError())["type"] == "server"
        assert classify_error(InvalidRequestError())["type"] == "invalid_request"

    def test_non_llm_error_type_is_unknown_but_class_name_preserved(self):
        info = classify_error(ValueError("bad"))
        assert info["type"] == "unknown"
        assert info["exception_class"] == "ValueError"

    def test_agent_state_propagated(self):
        exc = RateLimitError("hit limit")
        exc.agent_state = {"iteration": 3, "tokens_used": 1234}
        info = classify_error(exc)
        assert info["agent_state"] == {"iteration": 3, "tokens_used": 1234}

    def test_missing_agent_state_not_in_dict(self):
        info = classify_error(RateLimitError())
        assert "agent_state" not in info


class TestOpenAntLLMError:
    def test_kwargs_become_attributes(self):
        exc = RateLimitError("msg", request_id="req-123", status_code=429)
        assert exc.request_id == "req-123"
        assert exc.status_code == 429

    def test_message_attribute_mirrors_str(self):
        exc = RateLimitError("hello")
        assert exc.message == "hello"
        assert str(exc) == "hello"

    def test_can_be_raised_and_caught_as_base(self):
        with pytest.raises(OpenAntLLMError):
            raise RateLimitError("x")
