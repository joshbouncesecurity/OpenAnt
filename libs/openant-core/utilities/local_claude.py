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
import re
import shutil
import subprocess
import sys
import uuid

from .file_io import run_utf8


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

    result = run_utf8(
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


# ---------------------------------------------------------------------------
# Tool-use simulation helpers
# ---------------------------------------------------------------------------

def _build_tool_system_prompt(tools: list, original_system: str = None) -> str:
    """Build a system prompt that includes tool definitions as text instructions.

    Args:
        tools: Tool definitions list (same format as TOOL_DEFINITIONS).
        original_system: The original system prompt to prepend.

    Returns:
        Combined system prompt with tool instructions.
    """
    parts = []
    if original_system:
        parts.append(original_system)

    parts.append("\n\n## Available Tools\n")
    parts.append("You have the following tools available. To call a tool, "
                 "wrap a JSON object in <tool_call> tags.\n")
    parts.append("Format: <tool_call>{\"name\": \"tool_name\", \"input\": {…}}</tool_call>\n")
    parts.append("You may call multiple tools in one response. "
                 "Call the `finish` tool when your analysis is complete.\n")

    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        schema = tool.get("input_schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        parts.append(f"\n### {name}\n{desc}\n")
        if properties:
            parts.append("Parameters:")
            for prop_name, prop_def in properties.items():
                req_marker = " (required)" if prop_name in required else ""
                prop_type = prop_def.get("type", "any")
                prop_desc = prop_def.get("description", "")
                parts.append(f"  - {prop_name} ({prop_type}{req_marker}): {prop_desc}")
        parts.append("")

    return "\n".join(parts)


def _serialize_messages(messages: list) -> str:
    """Serialize multi-turn message history into a single text prompt.

    Handles both dict-based blocks (from agent.py message construction) and
    attribute-based objects (from response.content appended back into messages).

    Args:
        messages: The messages list from the API call.

    Returns:
        A single string prompt for claude -p.
    """
    parts = []

    for msg in messages:
        role = msg.get("role", "user") if isinstance(msg, dict) else "user"
        content = msg.get("content", "") if isinstance(msg, dict) else msg

        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                # Dict-based blocks (user messages, tool_result)
                if isinstance(block, dict):
                    block_type = block.get("type", "")
                    if block_type == "text":
                        parts.append(block.get("text", ""))
                    elif block_type == "tool_result":
                        tool_id = block.get("tool_use_id", "?")
                        result_content = block.get("content", "")
                        parts.append(f"Tool result (id: {tool_id}):\n{result_content}")
                # Attribute-based objects (from response.content)
                else:
                    obj_type = getattr(block, "type", "")
                    if obj_type == "tool_use":
                        name = getattr(block, "name", "?")
                        inp = getattr(block, "input", {})
                        parts.append(f"I called {name} with: {json.dumps(inp)}")
                    elif obj_type == "text":
                        parts.append(getattr(block, "text", ""))

    return "\n\n".join(parts)


def _parse_tool_calls(text: str) -> tuple:
    """Parse <tool_call> blocks from text response.

    Args:
        text: Raw text response from claude CLI.

    Returns:
        Tuple of (tool_use_blocks, remaining_text).
        tool_use_blocks: list of objects with .type, .name, .input, .id attributes.
        remaining_text: text with <tool_call> blocks removed.
    """
    pattern = r'<tool_call>\s*(.*?)\s*</tool_call>'
    matches = re.findall(pattern, text, re.DOTALL)

    tool_blocks = []
    for match in matches:
        try:
            data = json.loads(match)
            name = data.get("name", "")
            inp = data.get("input", {})
            block_id = f"toolu_{uuid.uuid4().hex[:24]}"
            block = type("ToolUseBlock", (), {
                "type": "tool_use",
                "name": name,
                "input": inp,
                "id": block_id,
            })()
            tool_blocks.append(block)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Warning: skipping malformed tool_call: {e}", file=sys.stderr)

    remaining = re.sub(pattern, "", text, flags=re.DOTALL).strip()
    return tool_blocks, remaining


class _Response:
    """Mimics an anthropic Message response."""

    def __init__(self, text=None, content=None, input_tokens=0, output_tokens=0,
                 stop_reason="end_turn"):
        if content is not None:
            self.content = content
        else:
            self.content = [type('TextBlock', (), {'type': 'text', 'text': text})()]
        self.usage = type('Usage', (), {
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
        })()
        self.stop_reason = stop_reason


class _Messages:
    """Mimics anthropic client.messages with .create()."""

    def create(self, **kwargs):
        tools = kwargs.get("tools", None)

        if tools:
            return self._create_with_tools(**kwargs)

        # Original text-only path
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

    def _create_with_tools(self, **kwargs):
        """Handle create() when tools are provided — simulate tool use via text."""
        tools = kwargs.get("tools", [])
        system_with_tools = _build_tool_system_prompt(tools, kwargs.get("system"))
        prompt = _serialize_messages(kwargs.get("messages", []))

        result = _run_claude_cli(
            prompt,
            model=kwargs.get("model", "claude-opus-4-20250514"),
            system=system_with_tools,
        )

        tool_blocks, remaining_text = _parse_tool_calls(result["text"])

        # Build content: text block (if any) + tool_use blocks
        content_blocks = []
        if remaining_text:
            content_blocks.append(
                type("TextBlock", (), {"type": "text", "text": remaining_text})()
            )
        content_blocks.extend(tool_blocks)

        # If no content at all, add empty text block
        if not content_blocks:
            content_blocks.append(
                type("TextBlock", (), {"type": "text", "text": ""})()
            )

        stop_reason = "tool_use" if tool_blocks else "end_turn"

        return _Response(
            content=content_blocks,
            input_tokens=result["input_tokens"],
            output_tokens=result["output_tokens"],
            stop_reason=stop_reason,
        )


class LocalClaudeClient:
    """Drop-in replacement for anthropic.Anthropic().

    Provides the same .messages.create() interface, routing calls through
    the claude CLI in print mode.
    """

    def __init__(self):
        self.messages = _Messages()
