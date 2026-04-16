"""
LLM Client

Routes all Claude API calls through the Claude Agent SDK, which handles
authentication automatically — either via ANTHROPIC_API_KEY (passed through
env) or the local Claude Code session.

Classes:
    TokenTracker: Tracks token usage and costs across multiple LLM calls
    AnthropicClient: Synchronous Claude API client with automatic token tracking

Usage:
    from utilities.llm_client import AnthropicClient, get_global_tracker

    client = AnthropicClient(model="claude-opus-4-6")
    response = client.analyze_sync("Analyze this code...")

    tracker = get_global_tracker()
    print(f"Total cost: ${tracker.total_cost_usd:.4f}")
"""

import json
import os
import sys
import threading
from typing import Optional
from dotenv import load_dotenv

# Load .env once at module level. Previously called in AnthropicClient.__init__,
# but load_dotenv() mutates os.environ which is not thread-safe under concurrent
# client construction. Runs at import time — tests that need to control env
# should mock os.environ or patch before importing this module.
load_dotenv()

from .rate_limiter import get_rate_limiter

from .model_config import MODEL_PRIMARY, MODEL_AUXILIARY, MODEL_DEFAULT


# Pricing per million tokens
MODEL_PRICING = {
    MODEL_PRIMARY: {"input": 15.00, "output": 75.00},
    MODEL_AUXILIARY: {"input": 3.00, "output": 15.00},
    # Fallback for unknown models (use Sonnet pricing as conservative estimate)
    "default": {"input": 3.00, "output": 15.00}
}


# ---------------------------------------------------------------------------
# SDK helpers (lazy imports to avoid breaking non-LLM commands like parse)
# ---------------------------------------------------------------------------

def _build_env() -> dict:
    """Build the env dict for ClaudeAgentOptions."""
    env = {}
    local_mode = os.getenv("OPENANT_LOCAL_CLAUDE", "").lower() == "true"

    # Pass API key only if not in local mode (local session auth takes precedence)
    if not local_mode:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            env["ANTHROPIC_API_KEY"] = api_key

    # Always forward CLAUDE_CONFIG_DIR — selects which Claude Code
    # profile/session to use (e.g. .claude-k)
    config_dir = os.getenv("CLAUDE_CONFIG_DIR")
    if config_dir:
        env["CLAUDE_CONFIG_DIR"] = config_dir
    # Prevent "nested session" error when running from within Claude Code
    env["CLAUDECODE"] = ""
    return env


def _build_options(model, system=None, max_turns=1, allowed_tools=None, **kwargs):
    """Build ClaudeAgentOptions with auth and config."""
    from claude_agent_sdk import ClaudeAgentOptions
    return ClaudeAgentOptions(
        model=model,
        system_prompt=system,
        max_turns=max_turns,
        allowed_tools=allowed_tools or [],
        permission_mode="bypassPermissions",
        env=_build_env(),
        **kwargs,
    )


async def _run_query(prompt, options, label=""):
    """Run a query via ClaudeSDKClient and return the response text.

    Uses the async context manager approach (NOT the query() generator)
    to avoid anyio cancel-scope errors.

    Args:
        prompt: The prompt text to send.
        options: ClaudeAgentOptions instance.
        label: Optional label for verbose log lines (e.g. unit ID).

    Returns:
        Tuple of (ResultMessage, last_assistant_text).
    """
    import time
    from claude_agent_sdk import ClaudeSDKClient, AssistantMessage, ResultMessage

    _verbose = os.getenv("OPENANT_VERBOSE", "").lower() == "true"
    tag = f"[SDK:{label}]" if label else "[SDK]"
    t0 = time.monotonic()

    if _verbose:
        print(f"  {tag} Connecting (model={options.model}, max_turns={options.max_turns})...",
              file=sys.stderr, flush=True)

    async with ClaudeSDKClient(options=options) as client:
        t_connect = time.monotonic()
        if _verbose:
            print(f"  {tag} Connected ({t_connect - t0:.1f}s). Sending query...",
                  file=sys.stderr, flush=True)

        await client.query(prompt)
        t_query = time.monotonic()
        if _verbose:
            print(f"  {tag} Query sent ({t_query - t_connect:.1f}s). Receiving messages...",
                  file=sys.stderr, flush=True)

        last_assistant_text = ""
        result_message = None
        turn_count = 0
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                turn_count += 1
                parts = []
                tool_names = []
                for block in getattr(message, "content", []):
                    if type(block).__name__ == "TextBlock":
                        parts.append(block.text)
                    elif type(block).__name__ == "ToolUseBlock":
                        tool_names.append(getattr(block, "name", "?"))
                if parts:
                    last_assistant_text = "\n".join(parts)
                if _verbose:
                    elapsed = time.monotonic() - t0
                    tools_str = f" tools=[{','.join(tool_names)}]" if tool_names else ""
                    text_preview = parts[0][:80] if parts else ""
                    print(f"  {tag} Turn {turn_count} ({elapsed:.1f}s){tools_str} {text_preview}",
                          file=sys.stderr, flush=True)
            elif isinstance(message, ResultMessage):
                result_message = message
                if _verbose:
                    elapsed = time.monotonic() - t0
                    cost = getattr(message, "total_cost_usd", None) or 0
                    turns = getattr(message, "num_turns", "?")
                    print(f"  {tag} Done ({elapsed:.1f}s total, {turns} turns, ${cost:.4f})",
                          file=sys.stderr, flush=True)

        return result_message, last_assistant_text


def _run_query_sync(prompt, options, label=""):
    """Synchronous wrapper around _run_query.

    Creates a fresh event loop per call so concurrent threads don't
    interfere with each other.
    """
    import asyncio
    return asyncio.run(_run_query(prompt, options, label=label))


# ---------------------------------------------------------------------------
# Native verification (SDK-backed, multi-turn with native tools)
# ---------------------------------------------------------------------------

def run_native_verification(
    prompt: str,
    system: str,
    model: str,
    repo_path: str,
    json_schema: dict = None,
    max_budget_usd: float = 0.30,
    timeout: int = 600,
) -> dict:
    """
    Run Claude Code in native multi-turn mode for verification.

    Lets Claude Code use its own native tools (Read, Grep, Glob, Bash)
    to explore the codebase and produce a structured JSON verdict.

    Args:
        prompt: The verification prompt.
        system: System prompt for the session.
        model: Model to use (e.g. "claude-opus-4-6").
        repo_path: Path to the repository root.
        json_schema: Optional JSON schema for structured output.
        max_budget_usd: Maximum dollar budget per finding.
        timeout: Not used with SDK (kept for API compat).

    Returns:
        Dict with 'text', 'input_tokens', 'output_tokens', 'cost_usd'.
    """
    extra = {}
    if json_schema:
        extra["output_format"] = {"type": "json_schema", "schema": json_schema}

    options = _build_options(
        model=model,
        system=system,
        max_turns=None,  # Let SDK decide (multi-turn)
        allowed_tools=["Read", "Grep", "Glob", "Bash"],
        add_dirs=[repo_path],
        cwd=repo_path,
        max_budget_usd=max_budget_usd,
        **extra,
    )

    result_message, last_text = _run_query_sync(prompt, options)

    if result_message is None:
        raise RuntimeError("SDK returned no ResultMessage")

    usage = result_message.usage or {}
    cost = result_message.total_cost_usd or 0.0

    # With json_schema, the verdict is in structured_output
    structured = getattr(result_message, "structured_output", None)
    if structured and isinstance(structured, dict):
        text = json.dumps(structured)
    elif result_message.result:
        text = result_message.result
    else:
        text = last_text

    return {
        "text": text,
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "cost_usd": cost,
    }


# ---------------------------------------------------------------------------
# Token tracking
# ---------------------------------------------------------------------------

class TokenTracker:
    """Tracks token usage and costs across LLM calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self.reset()

    def reset(self):
        """Reset all counters."""
        with self._lock:
            self.calls = []
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_usd = 0.0

    def restore_from(self, totals: dict):
        """Restore counters from a previously saved totals dict (e.g. checkpoint).

        Args:
            totals: Dict with total_input_tokens, total_output_tokens, total_cost_usd.
        """
        with self._lock:
            self.total_input_tokens = totals.get("total_input_tokens", 0)
            self.total_output_tokens = totals.get("total_output_tokens", 0)
            self.total_cost_usd = totals.get("total_cost_usd", 0.0)

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.total_input_tokens + self.total_output_tokens

    def record_call(self, model: str, input_tokens: int, output_tokens: int,
                    cost_usd: float = None) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            cost_usd: Actual cost from the SDK. If provided, used directly
                      instead of calculating from token counts and pricing table.

        Returns:
            Dict with call details including cost
        """
        if cost_usd is not None:
            total_cost = cost_usd
        else:
            pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
            input_cost = (input_tokens / 1_000_000) * pricing["input"]
            output_cost = (output_tokens / 1_000_000) * pricing["output"]
            total_cost = input_cost + output_cost

        call_record = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(total_cost, 6)
        }

        # Update totals (thread-safe)
        with self._lock:
            self.calls.append(call_record)
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += total_cost

        # Accumulate to thread-local unit tracking if active
        tl = self._thread_local
        if hasattr(tl, "unit_input"):
            tl.unit_input += input_tokens
            tl.unit_output += output_tokens
            tl.unit_cost += total_cost

        return call_record

    def add_prior_usage(self, input_tokens: int, output_tokens: int, cost_usd: float):
        """Inject usage from a prior run (e.g. restored checkpoints).

        This ensures step reports capture the total cost across all runs,
        not just the current run's API calls.
        """
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += cost_usd

    def start_unit_tracking(self):
        """Start tracking usage for the current unit on this thread.

        Call before processing a unit, then call ``get_unit_usage()``
        after to get the accumulated usage for just that unit. Thread-safe
        because each thread has its own ``threading.local()`` storage.
        """
        tl = self._thread_local
        tl.unit_input = 0
        tl.unit_output = 0
        tl.unit_cost = 0.0

    def get_unit_usage(self) -> dict:
        """Return usage accumulated since ``start_unit_tracking()`` on this thread."""
        tl = self._thread_local
        return {
            "input_tokens": getattr(tl, "unit_input", 0),
            "output_tokens": getattr(tl, "unit_output", 0),
            "cost_usd": round(getattr(tl, "unit_cost", 0.0), 6),
        }

    def get_summary(self) -> dict:
        """
        Get summary of all tracked calls.

        Returns:
            Dict with totals and per-call breakdown
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "calls": list(self.calls),
            }

    def get_totals(self) -> dict:
        """
        Get just the totals (without per-call breakdown).

        Returns:
            Dict with totals only
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
            }


# Global tracker instance for session-wide tracking
_global_tracker = TokenTracker()


def get_global_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _global_tracker


def reset_global_tracker():
    """Reset the global token tracker."""
    _global_tracker.reset()


# ---------------------------------------------------------------------------
# Client classes
# ---------------------------------------------------------------------------

def _log_auth_mode():
    """Print which auth mode is in use (once per client creation)."""
    local_mode = os.getenv("OPENANT_LOCAL_CLAUDE", "").lower() == "true"
    api_key = os.getenv("ANTHROPIC_API_KEY")
    config_dir = os.getenv("CLAUDE_CONFIG_DIR")
    if local_mode:
        if config_dir:
            print(f"Using Claude Agent SDK (local session, config: {config_dir})", file=sys.stderr)
        else:
            print("Using Claude Agent SDK (local session)", file=sys.stderr)
    elif api_key:
        print("Using Claude Agent SDK (API key mode)", file=sys.stderr)
    else:
        print("Using Claude Agent SDK (local session)", file=sys.stderr)


def create_message(prompt: str, model: str, system: str = None, max_tokens: int = 8192,
                   **kwargs) -> str:
    """Send a single-turn message and return the text content.

    This is a convenience function for callers that don't need token tracking.
    For tracked calls, use AnthropicClient instead.
    """
    options = _build_options(
        model=model,
        system=system,
        max_turns=1,
        allowed_tools=[],
    )
    result_message, last_text = _run_query_sync(prompt, options)

    if result_message and result_message.result:
        return result_message.result
    return last_text


class AnthropicClient:
    """
    Client for Claude API with automatic token tracking.

    Routes all calls through the Claude Agent SDK. Authentication is
    automatic: uses ANTHROPIC_API_KEY if set, otherwise the local
    Claude Code session.
    """

    def __init__(self, model: str = MODEL_DEFAULT, tracker: TokenTracker = None):
        """
        Initialize the client.

        Args:
            model: Model identifier. Defaults to MODEL_DEFAULT from model_config.
            tracker: Optional TokenTracker instance. Uses global tracker if not provided.
        """
        _log_auth_mode()
        self.model = model
        self.tracker = tracker or _global_tracker
        self.last_call = None

    def _call(self, model: str, prompt: str, system: str = None, max_tokens: int = 8192) -> str:
        """Make an API call, track usage, and return the response text."""
        options = _build_options(
            model=model,
            system=system,
            max_turns=1,
            allowed_tools=[],
        )
        result_message, last_text = _run_query_sync(prompt, options)

        # Extract usage and cost from SDK
        usage = (result_message.usage or {}) if result_message else {}
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        cost_usd = (result_message.total_cost_usd or 0.0) if result_message else None

        self.last_call = self.tracker.record_call(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
        )

        if result_message and result_message.result:
            return result_message.result
        return last_text

    async def analyze(self, prompt: str, max_tokens: int = 8192) -> str:
        """
        Send a prompt to Claude and get a response.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response

        Returns:
            Response text from Claude
        """
        return self._call(self.model, prompt, max_tokens=max_tokens)

    def analyze_sync(self, prompt: str, max_tokens: int = 8192, model: str = None, system: str = None) -> str:
        """
        Synchronous version of analyze.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response
            model: Optional model override (uses instance model if not specified)
            system: Optional system prompt for context/instructions

        Returns:
            Response text from Claude
        """
        return self._call(model or self.model, prompt, system=system, max_tokens=max_tokens)

    def get_last_call(self) -> Optional[dict]:
        """Get details of the last API call."""
        return self.last_call

    def get_session_totals(self) -> dict:
        """Get cumulative totals for this session."""
        return self.tracker.get_totals()

    def get_session_summary(self) -> dict:
        """Get full summary including per-call breakdown."""
        return self.tracker.get_summary()
