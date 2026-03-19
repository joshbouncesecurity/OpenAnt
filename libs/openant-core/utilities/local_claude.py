"""
Local Claude Code client.

Provides a drop-in replacement for anthropic.Anthropic() that routes calls
through the local Claude Code CLI (`claude -p`). Uses the local session's
authentication — no API key needed.

Enable by setting OPENANT_LOCAL_CLAUDE=true and CLAUDE_CONFIG_DIR in the
environment (or .env file).
"""

import json
import os
import shutil
import subprocess


def is_enabled() -> bool:
    """Check if local Claude Code mode is enabled."""
    return os.getenv("OPENANT_LOCAL_CLAUDE", "").lower() == "true"


def _run_claude_cli(prompt: str, model: str, system: str = None) -> dict:
    """
    Call the claude CLI in print mode and return parsed results.

    Returns:
        Dict with 'text', 'input_tokens', 'output_tokens', 'cost_usd'.
    """
    claude_bin = shutil.which("claude")
    if not claude_bin:
        raise FileNotFoundError(
            "claude CLI not found on PATH. Install Claude Code first."
        )

    full_prompt = prompt
    if system:
        full_prompt = f"{system}\n\n{prompt}"

    cmd = [
        claude_bin, "-p", full_prompt,
        "--model", model,
        "--max-turns", "1",
        "--output-format", "json",
    ]

    # Unset CLAUDECODE to allow spawning from within a Claude Code session
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"claude CLI failed (exit {result.returncode}): {stderr}")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("claude CLI returned no output")

    try:
        data = json.loads(stdout)
        usage = data.get("usage", {})
        return {
            "text": data.get("result", "") or stdout,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "cost_usd": data.get("total_cost_usd", 0.0),
        }
    except json.JSONDecodeError:
        return {
            "text": stdout,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
        }


class _Response:
    """Mimics an anthropic Message response."""

    def __init__(self, text, input_tokens=0, output_tokens=0):
        self.content = [type('TextBlock', (), {'type': 'text', 'text': text})()]
        self.usage = type('Usage', (), {
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
        })()
        self.stop_reason = "end_turn"


class _Messages:
    """Mimics anthropic client.messages with .create()."""

    def create(self, **kwargs):
        messages = kwargs.get("messages", [])
        prompt = ""
        for msg in messages:
            if msg["role"] == "user":
                content = msg["content"]
                if isinstance(content, str):
                    prompt = content
                elif isinstance(content, list):
                    prompt = " ".join(
                        block["text"] for block in content
                        if isinstance(block, dict) and block.get("type") == "text"
                    )
        result = _run_claude_cli(
            prompt,
            model=kwargs.get("model", "claude-opus-4-20250514"),
            system=kwargs.get("system"),
        )
        return _Response(
            result["text"],
            input_tokens=result["input_tokens"],
            output_tokens=result["output_tokens"],
        )


class LocalClaudeClient:
    """Drop-in replacement for anthropic.Anthropic().

    Provides the same .messages.create() interface, routing calls through
    the claude CLI in print mode.
    """

    def __init__(self):
        self.messages = _Messages()
