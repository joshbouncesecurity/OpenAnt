"""
Agentic Context Enhancer

Uses the Claude Agent SDK with native tools (Read, Grep, Glob, Bash) to
explore the codebase and gather context for security analysis. Static
dependencies are pre-resolved from the RepositoryIndex and included in
the prompt so the model has a head start before exploring.

Supports reachability-aware classification to distinguish:
- EXPLOITABLE: Vulnerable + reachable from user input
- VULNERABLE_INTERNAL: Vulnerable but not user-reachable
- SECURITY_CONTROL: Defensive code
- NEUTRAL: No security relevance
"""

import json
import re
import sys
from typing import Optional, Set, List

from ..llm_client import TokenTracker, get_global_tracker
from ..sdk_errors import RateLimitError
from .repository_index import RepositoryIndex
from .tools import ToolExecutor
from .prompts import SYSTEM_PROMPT, get_user_prompt
from .entry_point_detector import EntryPointDetector
from .reachability_analyzer import ReachabilityAnalyzer


# Use Sonnet for exploration (cost-effective)
AGENT_MODEL = "claude-sonnet-4-20250514"

# Safety limits
MAX_TURNS = 20


# JSON schema for structured agent output
AGENT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "include_functions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Function identifier in format 'relative/path.ext:functionName'",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why this function is needed for context",
                    },
                },
                "required": ["id", "reason"],
            },
        },
        "usage_context": {"type": "string"},
        "security_classification": {
            "type": "string",
            "enum": ["exploitable", "vulnerable_internal", "security_control", "neutral"],
        },
        "classification_reasoning": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": [
        "include_functions",
        "usage_context",
        "security_classification",
        "classification_reasoning",
        "confidence",
    ],
}


class AgentResult:
    """Result from agent analysis."""

    def __init__(
        self,
        include_functions: list[dict],
        usage_context: str,
        security_classification: str,
        classification_reasoning: str,
        confidence: float,
        iterations: int,
        total_tokens: int,
        is_entry_point: bool = False,
        reachable_from_entry: Optional[bool] = None,
        entry_point_path: Optional[List[str]] = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ):
        self.include_functions = include_functions
        self.usage_context = usage_context
        self.security_classification = security_classification
        self.classification_reasoning = classification_reasoning
        self.confidence = confidence
        self.iterations = iterations
        self.total_tokens = total_tokens
        self.is_entry_point = is_entry_point
        self.reachable_from_entry = reachable_from_entry
        self.entry_point_path = entry_point_path
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "include_functions": self.include_functions,
            "usage_context": self.usage_context,
            "security_classification": self.security_classification,
            "classification_reasoning": self.classification_reasoning,
            "confidence": self.confidence,
            "agent_metadata": {
                "iterations": self.iterations,
                "total_tokens": self.total_tokens,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd,
            },
            "reachability": {
                "is_entry_point": self.is_entry_point,
                "reachable_from_entry": self.reachable_from_entry,
                "entry_point_path": self.entry_point_path,
            },
        }


def _pre_resolve_deps(tool_executor: ToolExecutor, static_deps: list, static_callers: list) -> str:
    """Pre-resolve static dependencies via ToolExecutor and format for prompt."""
    tool_executor.set_unit_context(static_deps, static_callers)
    resolved = tool_executor.execute("get_static_dependencies", {})
    parts = []
    for label, key in [("Resolved Dependencies", "dependencies"), ("Resolved Callers", "callers")]:
        items = resolved.get(key, {}).get("resolved", [])
        if items:
            parts.append(f"### {label} (from parsed index)")
            for item in items[:15]:
                if isinstance(item, dict):
                    parts.append(f"- `{item.get('id', item.get('name', '?'))}` ({item.get('file', '')})")
                else:
                    parts.append(f"- `{item}`")
    return "\n".join(parts) if parts else ""


def _try_parse_json(text: str) -> Optional[dict]:
    """Try to extract JSON from text, handling code blocks."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    match = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


class ContextAgent:
    """
    Agent that explores codebase to gather context for security analysis.
    Uses Claude Agent SDK with native tools (Read, Grep, Glob, Bash) to
    trace call paths and understand code intent. Static dependencies are
    pre-resolved from the RepositoryIndex and included in the prompt.

    Supports reachability-aware classification when entry_points and
    reachability analyzer are provided.
    """

    def __init__(
        self,
        index: RepositoryIndex,
        tracker: TokenTracker = None,
        verbose: bool = False,
        entry_points: Optional[Set[str]] = None,
        reachability: Optional[ReachabilityAnalyzer] = None,
    ):
        """
        Initialize the agent.

        Args:
            index: RepositoryIndex for searching code
            tracker: TokenTracker for cost tracking
            verbose: If True, print debug information
            entry_points: Set of func_ids that are entry points (optional)
            reachability: ReachabilityAnalyzer for checking user input paths (optional)
        """
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.tool_executor = ToolExecutor(index)
        self.entry_points = entry_points or set()
        self.reachability = reachability

    def analyze_unit(
        self,
        unit_id: str,
        unit_type: str,
        primary_code: str,
        static_deps: list[str],
        static_callers: list[str],
    ) -> AgentResult:
        """
        Analyze a code unit using Claude Agent SDK with native tools.

        Args:
            unit_id: Function identifier
            unit_type: Type classification
            primary_code: Code with static dependencies
            static_deps: Static analysis dependencies
            static_callers: Static analysis callers

        Returns:
            AgentResult with gathered context
        """
        # Lazy import to avoid breaking non-LLM commands at import time.
        from ..llm_client import _run_query_sync, _build_options

        # Compute reachability info
        is_entry_point = unit_id in self.entry_points
        reachable_from_entry: Optional[bool] = None
        entry_point_path: Optional[List[str]] = None
        reaching_entry_point: Optional[str] = None

        if self.reachability:
            reachable_from_entry = self.reachability.is_reachable_from_entry_point(unit_id)
            if reachable_from_entry:
                entry_point_path = self.reachability.get_entry_point_path(unit_id)
                reaching_entry_point = self.reachability.get_reaching_entry_point(unit_id)

        # Pre-resolve static deps from the index so the model has a head start
        resolved_context = _pre_resolve_deps(self.tool_executor, static_deps, static_callers)

        user_prompt = get_user_prompt(
            unit_id=unit_id,
            unit_type=unit_type,
            primary_code=primary_code,
            static_deps=static_deps,
            static_callers=static_callers,
            is_entry_point=is_entry_point,
            reachable_from_entry=reachable_from_entry,
            entry_point_path=entry_point_path,
            reaching_entry_point=reaching_entry_point,
        )
        if resolved_context:
            user_prompt += f"\n\n{resolved_context}"

        repo_path = str(self.index.repo_path) if self.index.repo_path else None

        options = _build_options(
            model=AGENT_MODEL,
            system=SYSTEM_PROMPT,
            max_turns=MAX_TURNS,
            allowed_tools=["Read", "Grep", "Glob", "Bash"],
            add_dirs=[repo_path] if repo_path else [],
            cwd=repo_path,
            output_format={"type": "json_schema", "schema": AGENT_OUTPUT_SCHEMA},
            max_budget_usd=0.50,
        )

        if self.verbose:
            print(f"  Analyzing {unit_id} via SDK...", file=sys.stderr, flush=True)

        try:
            result_message, last_text = _run_query_sync(user_prompt, options, label=unit_id)
        except RateLimitError as exc:
            # Rate limit is already reported to GlobalRateLimiter inside _run_query.
            # Attach agent state so the caller (checkpoint/resume) knows how far we got.
            exc.agent_state = {
                "unit_id": unit_id,
                "tokens_used": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            raise
        except Exception as exc:
            # Attach agent state for non-rate-limit errors too (checkpoint telemetry).
            exc.agent_state = {
                "unit_id": unit_id,
                "tokens_used": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            raise

        # Track usage via the SDK-reported totals
        usage = (result_message.usage or {}) if result_message else {}
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        total_tokens = input_tokens + output_tokens
        cost_usd_sdk = (result_message.total_cost_usd or 0.0) if result_message else None

        call_record = self.tracker.record_call(
            model=AGENT_MODEL,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd_sdk,
        )
        call_cost = call_record.get("cost_usd", 0.0)

        # Parse structured output (preferred) or fall back to text + JSON extraction
        parsed: Optional[dict] = None
        structured = getattr(result_message, "structured_output", None) if result_message else None
        if structured and isinstance(structured, dict):
            parsed = structured
        if not parsed:
            raw_text = (
                result_message.result
                if result_message and result_message.result
                else last_text or ""
            )
            if raw_text:
                parsed = _try_parse_json(raw_text)

        # Num turns from SDK (for telemetry parity with the old iterations field)
        num_turns = (
            getattr(result_message, "num_turns", 0) if result_message else 0
        ) or 0

        if parsed and "security_classification" in parsed:
            if self.verbose:
                print(
                    f"  Classification: {parsed['security_classification']} "
                    f"(confidence: {parsed.get('confidence', '?')})",
                    file=sys.stderr,
                    flush=True,
                )
            return AgentResult(
                include_functions=parsed.get("include_functions", []),
                usage_context=parsed.get("usage_context", ""),
                security_classification=parsed.get("security_classification", "neutral"),
                classification_reasoning=parsed.get("classification_reasoning", ""),
                confidence=parsed.get("confidence", 0.5),
                iterations=num_turns,
                total_tokens=total_tokens,
                is_entry_point=is_entry_point,
                reachable_from_entry=reachable_from_entry,
                entry_point_path=entry_point_path,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=call_cost,
            )

        if self.verbose:
            print("  Could not parse agent response", file=sys.stderr, flush=True)
        return AgentResult(
            include_functions=[],
            usage_context="Could not parse agent response",
            security_classification="neutral",
            classification_reasoning="Analysis response unparseable",
            confidence=0.2,
            iterations=num_turns,
            total_tokens=total_tokens,
            is_entry_point=is_entry_point,
            reachable_from_entry=reachable_from_entry,
            entry_point_path=entry_point_path,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=call_cost,
        )


def enhance_unit_with_agent(
    unit: dict,
    index: RepositoryIndex,
    tracker: TokenTracker = None,
    verbose: bool = False,
    entry_points: Optional[Set[str]] = None,
    reachability: Optional[ReachabilityAnalyzer] = None,
) -> dict:
    """
    Enhance a single unit using the agentic approach.

    Mutates ``unit`` in place: attaches ``agent_context`` and, if the agent
    identified additional functions, extends ``unit["code"]["primary_code"]``
    with those definitions.

    Args:
        unit: Unit from dataset (mutated in place)
        index: Repository index for searching
        tracker: Token tracker
        verbose: Print debug info
        entry_points: Set of func_ids that are entry points (optional)
        reachability: ReachabilityAnalyzer for checking user input paths (optional)

    Returns:
        The same unit dict, with agent_context field including reachability info
    """
    agent = ContextAgent(
        index=index,
        tracker=tracker,
        verbose=verbose,
        entry_points=entry_points,
        reachability=reachability,
    )

    # Extract unit info
    unit_id = unit.get("id", "unknown")
    unit_type = unit.get("unit_type", "function")
    code_section = unit.get("code", {})
    primary_code = (
        code_section
        if isinstance(code_section, str)
        else code_section.get("primary_code", "")
    )
    metadata = unit.get("metadata", {})
    if isinstance(metadata, str):
        static_deps, static_callers = [], []
    else:
        static_deps = metadata.get("direct_calls", [])
        static_callers = metadata.get("direct_callers", [])

    # Run agent
    result = agent.analyze_unit(
        unit_id=unit_id,
        unit_type=unit_type,
        primary_code=primary_code,
        static_deps=static_deps,
        static_callers=static_callers,
    )

    # Add result to unit
    unit["agent_context"] = result.to_dict()

    # Assemble additional code if functions were identified
    if result.include_functions and isinstance(unit.get("code"), dict):
        additional_code = []
        additional_files = set()

        for func_info in result.include_functions:
            func_id = func_info if isinstance(func_info, str) else func_info.get("id", "")
            func_data = index.get_function(func_id)

            # Fuzzy match: SDK native tools may return IDs that don't match the
            # index exactly (e.g. "file.py:Class.method" vs index's "file.py:method").
            if not func_data and func_id:
                name_part = func_id.rsplit(":", 1)[-1] if ":" in func_id else func_id
                if "." in name_part:
                    name_part = name_part.rsplit(".", 1)[-1]
                matches = index.search_by_name(name_part, exact=True)
                if not matches:
                    matches = index.search_by_name(name_part, exact=False)
                if matches:
                    func_data = matches[0]
                    func_id = func_data.get("id", func_id)

            if func_data and func_data.get("code"):
                additional_code.append(func_data["code"])

                # Extract file path from func_id
                colon_idx = func_id.rfind(":")
                if colon_idx > 0:
                    additional_files.add(func_id[:colon_idx])

        # Append to primary_code with file boundaries
        if additional_code:
            FILE_BOUNDARY = "\n\n// ========== File Boundary ==========\n\n"
            current_code = unit["code"].get("primary_code", "")
            assembled = current_code + FILE_BOUNDARY + FILE_BOUNDARY.join(additional_code)
            unit["code"]["primary_code"] = assembled

            # Update metadata
            origin = unit["code"].get("primary_origin", {})
            current_files = set(origin.get("files_included", []))
            origin["files_included"] = list(current_files | additional_files)
            origin["deps_inlined"] = True
            origin["enhanced_length"] = len(assembled)
            unit["code"]["primary_origin"] = origin

    return unit


def create_reachability_context(
    functions: dict,
    call_graph: dict,
    reverse_call_graph: dict,
) -> tuple[Set[str], ReachabilityAnalyzer]:
    """
    Create entry points and reachability analyzer from call graph data.

    This is a convenience function to set up reachability analysis
    from the output of CallGraphBuilder.

    Args:
        functions: Dict mapping func_id to function metadata
        call_graph: Forward call graph (func_id -> [called_func_ids])
        reverse_call_graph: Reverse call graph (func_id -> [caller_func_ids])

    Returns:
        Tuple of (entry_points, reachability_analyzer)

    Example:
        # From call graph builder output
        entry_points, reachability = create_reachability_context(
            functions=call_graph_data['functions'],
            call_graph=call_graph_data['call_graph'],
            reverse_call_graph=call_graph_data['reverse_call_graph']
        )

        # Use with enhance_unit_with_agent
        enhanced = enhance_unit_with_agent(
            unit, index,
            entry_points=entry_points,
            reachability=reachability
        )
    """
    # Detect entry points
    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()

    # Create reachability analyzer
    reachability = ReachabilityAnalyzer(
        functions=functions,
        reverse_call_graph=reverse_call_graph,
        entry_points=entry_points,
    )

    return entry_points, reachability
