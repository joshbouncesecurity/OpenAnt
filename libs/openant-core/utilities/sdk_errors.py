"""SDK error taxonomy.

Replaces the `anthropic.*Error` hierarchy that scattered through the codebase
pre-migration. The Claude Agent SDK surfaces API-level errors through
`AssistantMessage.error: AssistantMessageError | None`, a Literal of
"authentication_failed", "billing_error", "rate_limit", "invalid_request",
"server_error", "unknown". We map each one onto an exception class so callers
can `except RateLimitError` instead of inspecting message fields.

Process-level errors (CLI not found, connection issues, JSON decode failures)
come through `claude_agent_sdk`'s own exception types and propagate up
unwrapped — they're not API errors.
"""

from typing import Any


class OpenAntLLMError(Exception):
    """Base class for LLM-layer errors that originated inside the model turn.

    Subclasses correspond 1:1 to `AssistantMessageError` literal values. Raised
    from `utilities.llm_client._run_query` when an AssistantMessage carries an
    `error` field.
    """

    error_kind: str = "unknown"

    def __init__(self, message: str = "", **kwargs: Any):
        super().__init__(message)
        self.message = message
        # Allow callers to attach arbitrary state (e.g. agent iteration counts).
        for key, value in kwargs.items():
            setattr(self, key, value)


class AuthError(OpenAntLLMError):
    """Maps to AssistantMessageError == "authentication_failed"."""

    error_kind = "authentication_failed"


class BillingError(OpenAntLLMError):
    """Maps to AssistantMessageError == "billing_error"."""

    error_kind = "billing_error"


class RateLimitError(OpenAntLLMError):
    """Maps to AssistantMessageError == "rate_limit".

    The SDK does not surface a `retry-after` value; callers that feed
    GlobalRateLimiter should pass 0 and let the default backoff apply.
    """

    error_kind = "rate_limit"


class InvalidRequestError(OpenAntLLMError):
    """Maps to AssistantMessageError == "invalid_request"."""

    error_kind = "invalid_request"


class ServerError(OpenAntLLMError):
    """Maps to AssistantMessageError == "server_error". Transient; safe to retry."""

    error_kind = "server_error"


class UnknownLLMError(OpenAntLLMError):
    """Maps to AssistantMessageError == "unknown". Fallback for unrecognized values."""

    error_kind = "unknown"


# Dispatch table for AssistantMessageError literal -> exception class.
_ERROR_KIND_TO_CLASS: dict[str, type[OpenAntLLMError]] = {
    "authentication_failed": AuthError,
    "billing_error": BillingError,
    "rate_limit": RateLimitError,
    "invalid_request": InvalidRequestError,
    "server_error": ServerError,
    "unknown": UnknownLLMError,
}


def error_from_kind(kind: str, message: str = "") -> OpenAntLLMError:
    """Construct the right exception subclass for an AssistantMessageError value.

    Unknown kinds fall back to UnknownLLMError.
    """
    cls = _ERROR_KIND_TO_CLASS.get(kind, UnknownLLMError)
    return cls(message or f"SDK reported error: {kind}")


def classify_error(exc: BaseException) -> dict:
    """Return a diagnostic dict for an OpenAntLLMError (or any exception).

    Shape matches what `utilities.context_enhancer` logged pre-migration, so
    existing callers can swap to this function without reshaping downstream
    consumers:

        {
            "type": "rate_limit" | "connection" | "timeout" | "api_status" | "unknown",
            "exception_class": "RateLimitError",
            "message": "...",
            ...
        }

    The pre-migration shape also carried `status_code`, `request_id`, and
    `retry_after` extracted from anthropic response headers. The SDK does not
    surface any of those, so we drop them.
    """
    info: dict = {
        "type": "unknown",
        "exception_class": type(exc).__name__,
        "message": str(exc),
    }

    if isinstance(exc, RateLimitError):
        info["type"] = "rate_limit"
    elif isinstance(exc, AuthError):
        info["type"] = "auth"
    elif isinstance(exc, BillingError):
        info["type"] = "billing"
    elif isinstance(exc, ServerError):
        info["type"] = "server"
    elif isinstance(exc, InvalidRequestError):
        info["type"] = "invalid_request"
    elif isinstance(exc, UnknownLLMError):
        info["type"] = "unknown"
    else:
        # Non-LLM error (process-level, SDK framework, caller bug). Leave
        # "type" as "unknown" but the class name still identifies it.
        pass

    agent_state = getattr(exc, "agent_state", None)
    if agent_state:
        info["agent_state"] = agent_state

    return info
