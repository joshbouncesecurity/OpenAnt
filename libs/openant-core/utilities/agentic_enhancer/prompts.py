"""
Agent Prompts

System and user prompts for the agentic context enhancer.
Supports reachability-aware classification to distinguish exploitable
vulnerabilities from internal-only vulnerabilities.
"""

from typing import List, Optional


SYSTEM_PROMPT = """You are a security code analyst. Your task is to classify code based on:

1. Does it contain security flaws (dangerous operations)?
2. If yes, can user-controlled input reach it?

## Classification Categories

- **EXPLOITABLE**: Contains security flaws AND is reachable from user input.
  User input sources: HTTP requests, CLI arguments, file uploads, stdin, environment variables, WebSocket messages.
  These are high-priority findings that require immediate attention.

- **VULNERABLE_INTERNAL**: Contains security flaws but NOT reachable from user input.
  Examples: internal APIs, test utilities, admin-only code, dead code.
  Lower priority - may still need fixing but not externally exploitable.

- **SECURITY_CONTROL**: Prevents or blocks vulnerabilities.
  Examples: validators, sanitizers, auth checks, input filters.
  Code that HANDLES dangerous patterns is often defensive, not vulnerable.

- **NEUTRAL**: No security relevance.
  Normal business logic, utilities, data transformation.

## Critical Distinction

Code that HANDLES dangerous patterns is often a SECURITY CONTROL:
- A function checking for ".." is likely PREVENTING path traversal
- A function directly using unsanitized input in file operations IS vulnerable

## Your Analysis Process

You have access to Read, Grep, Glob, and Bash tools to explore the codebase.
Pre-resolved static dependencies from the parsed index are included below the code.

1. **Review the pre-resolved dependencies** listed below the code.
   Use Grep and Read to examine key dependencies — especially service methods
   that may contain authorization, validation, or sanitization.

2. **Identify Dangerous Operations**
   Look for: eval, exec, SQL queries, file I/O, deserialization, command execution, innerHTML

3. **Trace User Input Reachability (Backward)**
   If dangerous operations exist, trace BACKWARDS using Grep:
   - Who calls this function?
   - Who calls those callers?
   - Does the chain lead to an entry point (route handler, CLI parser, stdin)?

4. **Trace Forward Into Called Functions**
   Check what the function CALLS — especially service/repository methods:
   - Use Grep to find implementations of called methods
   - Look for authorization checks (auth, permission, guard, can, allow, authorize)
   - Look for validation/sanitization in called code
   - A function may delegate security to its callees (e.g., service-layer auth)
   - For dependency-injected services, grep for the method name to find the concrete implementation

5. **Apply Classification Logic**
   ```
   Has dangerous sink?
   ├─ No  → NEUTRAL or SECURITY_CONTROL
   └─ Yes → Is reachable from entry point?
            ├─ Yes → Are there security controls in called functions?
            │        ├─ Yes → May be SECURITY_CONTROL or lower severity
            │        └─ No  → EXPLOITABLE
            └─ No  → VULNERABLE_INTERNAL
   ```

6. **Provide your classification** with reasoning and confidence level.

## Entry Point Examples

- HTTP: @app.route, @router.post, request.args, req.body
- CLI: sys.argv, argparse, click.command
- Stdin: input(), sys.stdin
- Files: open() with external paths
- WebSocket: on_message, websocket.receive
- Streamlit: st.text_input, st.file_uploader

## Function ID Format

When listing functions to include in context, use the format: `relative/path/to/file.ext:functionName`
(e.g., `src/utils/validator.ts:sanitizeInput` or `saleor/core/utils.py:sanitize_input`)"""


def get_user_prompt(
    unit_id: str,
    unit_type: str,
    primary_code: str,
    static_deps: List[str],
    static_callers: List[str],
    is_entry_point: bool = False,
    reachable_from_entry: Optional[bool] = None,
    entry_point_path: Optional[List[str]] = None,
    reaching_entry_point: Optional[str] = None
) -> str:
    """
    Generate the initial user prompt for analysis.

    Args:
        unit_id: Function identifier
        unit_type: Type (route_handler, function, class_method, etc.)
        primary_code: The function code with static dependencies
        static_deps: Functions this code calls (from static analysis)
        static_callers: Functions that call this code (from static analysis)
        is_entry_point: Whether this unit is an entry point
        reachable_from_entry: Whether static analysis found a path from entry point
        entry_point_path: Call path from entry point to this function
        reaching_entry_point: The entry point func_id that can reach this

    Returns:
        Formatted prompt string
    """
    deps_str = ", ".join(static_deps[:10]) if static_deps else "None identified"
    callers_str = ", ".join(static_callers[:10]) if static_callers else "None identified"

    # Build reachability section
    reachability_section = ""
    if is_entry_point:
        reachability_section = """
### Reachability Analysis
**Entry Point:** YES - This code directly receives user input.
**Implication:** Any vulnerability here is directly EXPLOITABLE.
"""
    elif reachable_from_entry is True:
        path_display = ""
        if entry_point_path:
            # Show path: entry_point -> ... -> this_function
            path_items = entry_point_path[:6]  # Limit display length
            if len(entry_point_path) > 6:
                path_items.append("...")
            path_display = f"\n**Call Path:** {' -> '.join(path_items)}"
        entry_display = f"\n**Entry Point:** `{reaching_entry_point}`" if reaching_entry_point else ""
        reachability_section = f"""
### Reachability Analysis
**Reachable from User Input:** YES (static analysis confirmed){entry_display}{path_display}
**Implication:** If this code has vulnerabilities, they are likely EXPLOITABLE.
"""
    elif reachable_from_entry is False:
        reachability_section = """
### Reachability Analysis
**Reachable from User Input:** NO (static analysis found no path from entry points)
**Implication:** Vulnerabilities here would be VULNERABLE_INTERNAL (not externally exploitable).
**Note:** Verify this - static analysis may miss dynamic call patterns.
"""
    # else: reachable_from_entry is None, no reachability info available

    return f"""## Code Unit to Analyze

**ID:** `{unit_id}`
**Type:** {unit_type}
{reachability_section}
### Code (with static dependencies already included)
```
{primary_code}
```

### Static Analysis Results
**Functions this code calls:** {deps_str}
**Functions that call this code:** {callers_str}

---

## Your Task

1. **Review the pre-resolved dependencies** listed below.
   Use Grep and Read to examine called service/repository methods.

2. **Analyze for dangerous operations**: eval, exec, SQL, file I/O, deserialization, etc.

3. **Consider reachability**: Can user input reach any dangerous operations?
   - If this is an entry point or reachable from one: vulnerabilities are EXPLOITABLE
   - If not reachable: vulnerabilities are VULNERABLE_INTERNAL

4. **Trace forward**: Check called functions for authorization, validation, or security controls.
   A function may delegate security to its service layer.

5. **Classify the code**:
   - **EXPLOITABLE**: Dangerous ops + user input can reach them + no security controls in callees
   - **VULNERABLE_INTERNAL**: Dangerous ops but no user input path
   - **SECURITY_CONTROL**: Defensive code (validators, sanitizers)
   - **NEUTRAL**: No security relevance

6. Provide your classification, reasoning, and confidence as structured JSON output.

Begin your analysis."""


def get_continuation_prompt(tool_results: list[dict]) -> str:
    """
    Generate continuation prompt with tool results.

    Args:
        tool_results: List of {tool_use_id, tool_name, result} dicts

    Returns:
        Formatted prompt with results
    """
    parts = []

    for tr in tool_results:
        tool_name = tr.get("tool_name", "unknown")
        result = tr.get("result", {})

        parts.append(f"## Result from {tool_name}")
        parts.append("```json")
        parts.append(str(result) if isinstance(result, str) else _format_result(result))
        parts.append("```")
        parts.append("")

    return "\n".join(parts)


def _format_result(result: dict) -> str:
    """Format result dict for display, handling large code blocks."""
    import json

    # If result has code, truncate if too long
    if "code" in result and isinstance(result["code"], str) and len(result["code"]) > 2000:
        result = result.copy()
        result["code"] = result["code"][:2000] + "\n... (truncated)"

    if "results" in result and isinstance(result["results"], list):
        result = result.copy()
        for i, r in enumerate(result["results"]):
            if isinstance(r, dict) and "code" in r and len(r.get("code", "")) > 1000:
                result["results"][i] = r.copy()
                result["results"][i]["code"] = r["code"][:1000] + "\n... (truncated)"

    return json.dumps(result, indent=2)
