"""
Stage 2 Finding Verifier (Enhanced)

Stage 2 of the two-stage vulnerability analysis pipeline.
Uses Opus with tool access to validate Stage 1 assessments by exploring
the codebase - searching function usages, reading definitions, and
tracing call paths.

Key Improvements:
    1. Explicit vulnerability definitions (exploitable NOW vs dangerous design)
    2. Required exploit path tracing (entry point -> sink)
    3. Consistency cross-check for similar code patterns
    4. Structured output with exploit_path field
    5. Batch verification with consistency validation

The verifier asks: "Can an attacker exploit this NOW in the current codebase?"
It validates by tracing the complete exploit path from attacker input to sink.

Available Tools:
    - search_usages: Find where a function is called
    - search_definitions: Find where a function is defined
    - read_function: Get full function code by ID
    - list_functions: List all functions in a file
    - finish: Complete verification with verdict and exploit path

Classes:
    VerificationResult: Dataclass containing verdict, exploit path, explanation
    FindingVerifier: Main verifier class with verify_result() and verify_batch() methods
"""

import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

import anthropic

from .llm_client import TokenTracker, get_global_tracker
from .rate_limiter import get_rate_limiter

# Null logger that discards all messages (used when no logger provided)
_null_logger = logging.getLogger("null_verifier")
_null_logger.addHandler(logging.NullHandler())
from .agentic_enhancer.repository_index import RepositoryIndex
from prompts.verification_prompts import (
    VERIFICATION_SYSTEM_PROMPT,
    VERIFICATION_JSON_SCHEMA,
    get_verification_prompt,
    get_verification_system_prompt,
    get_native_claude_verification_prompt,
    get_consistency_check_prompt
)

# Import application context type for type hints
try:
    from context.application_context import ApplicationContext
except ImportError:
    ApplicationContext = None


from .model_config import MODEL_PRIMARY
VERIFIER_MODEL = MODEL_PRIMARY
MAX_TOKENS_PER_RESPONSE = 4096


@dataclass
class ExploitPath:
    """Structured exploit path analysis."""
    entry_point: Optional[str] = None
    data_flow: list = field(default_factory=list)
    sink_reached: bool = False
    attacker_control_at_sink: str = "none"  # "full", "partial", "none"
    path_broken_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "entry_point": self.entry_point,
            "data_flow": self.data_flow,
            "sink_reached": self.sink_reached,
            "attacker_control_at_sink": self.attacker_control_at_sink,
            "path_broken_at": self.path_broken_at
        }

    def is_complete(self) -> bool:
        """Check if exploit path is complete (exploitable)."""
        return (
            self.entry_point is not None and
            self.sink_reached and
            self.attacker_control_at_sink in ["full", "partial"] and
            self.path_broken_at is None
        )


@dataclass
class VerificationResult:
    """Result from Stage 2 verification."""
    agree: bool
    correct_finding: str
    explanation: str
    iterations: int
    total_tokens: int
    exploit_path: Optional[ExploitPath] = None
    security_weakness: Optional[str] = None
    raw_response: Optional[str] = None  # Full Claude Code response (not serialized)

    def to_dict(self) -> dict:
        result = {
            "agree": self.agree,
            "correct_finding": self.correct_finding,
            "explanation": self.explanation,
            "iterations": self.iterations,
            "total_tokens": self.total_tokens
        }
        if self.exploit_path:
            result["exploit_path"] = self.exploit_path.to_dict()
        if self.security_weakness:
            result["security_weakness"] = self.security_weakness
        return result


@dataclass
class ConsistencyCheckResult:
    """Result from consistency cross-check."""
    pattern_identified: str
    consistent_verdict: str
    findings_updated: list
    explanation: str

    def to_dict(self) -> dict:
        return {
            "pattern_identified": self.pattern_identified,
            "consistent_verdict": self.consistent_verdict,
            "findings_updated": self.findings_updated,
            "explanation": self.explanation
        }


class FindingVerifier:
    """Validates Stage 1 assessments using Opus with tool access."""

    def __init__(
        self,
        index: RepositoryIndex,
        tracker: TokenTracker = None,
        verbose: bool = False,
        app_context: "ApplicationContext" = None,
        logger: logging.Logger = None,
        client: "anthropic.Anthropic | None" = None,
    ):
        self.index = index
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.app_context = app_context
        self.tool_executor = ToolExecutor(index)
        self.client = client or anthropic.Anthropic(max_retries=5)
        self.logger = logger or _null_logger
        self._use_logger = logger is not None

    def _save_explanation(self, route_key: str, verification: "VerificationResult"):
        """Save verification explanation to a file in the output directory."""
        verify_dir = os.path.join(self.output_dir, "verify_explanations")
        os.makedirs(verify_dir, exist_ok=True)

        # Sanitize route_key for use as filename
        safe_name = re.sub(r'[\\/:*?"<>|]', '_', route_key)
        filepath = os.path.join(verify_dir, f"{safe_name}.md")

        content = f"# {route_key}\n\n"
        content += f"**Verdict:** {verification.correct_finding}\n"
        content += f"**Agrees with Stage 1:** {verification.agree}\n\n"
        if verification.exploit_path:
            ep = verification.exploit_path
            content += "## Exploit Path\n\n"
            if ep.entry_point:
                content += f"**Entry point:** {ep.entry_point}\n\n"
            if ep.data_flow:
                content += "**Data flow:**\n"
                for step in ep.data_flow:
                    content += f"1. {step}\n"
                content += "\n"
            content += f"**Sink reached:** {ep.sink_reached}\n"
            content += f"**Attacker control at sink:** {ep.attacker_control_at_sink}\n"
            if ep.path_broken_at:
                content += f"**Path broken at:** {ep.path_broken_at}\n"
            content += "\n"
        content += "## Explanation\n\n"
        content += verification.explanation + "\n"
        if verification.security_weakness:
            content += f"\n## Security Weakness\n\n{verification.security_weakness}\n"

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[Verify] Saved explanation: {filepath}",
                  file=__import__('sys').stderr, flush=True)
        except OSError as e:
            print(f"[Verify] Could not save explanation for {route_key}: {e}",
                  file=__import__('sys').stderr, flush=True)

    def _log(self, level: str, msg: str, **extras):
        """Log a message, using logger if available, otherwise print if verbose."""
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        elif self.verbose:
            # Fallback to print for CLI usage (stderr to avoid corrupting JSON stdout)
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"    {msg} {suffix}" if suffix else f"    {msg}",
                  file=__import__('sys').stderr, flush=True)

    def verify_result(
        self,
        code: str,
        finding: str,
        attack_vector: str,
        reasoning: str,
        files_included: list = None
    ) -> VerificationResult:
        """
        Validate a Stage 1 assessment with exploit path tracing.

        Args:
            code: The code that was assessed
            finding: Stage 1's finding
            attack_vector: Stage 1's attack vector
            reasoning: Stage 1's reasoning
            files_included: Optional list of files in context

        Returns:
            VerificationResult with verdict, exploit path, and explanation
        """
        # SDK handles both API key and local session modes — always use
        # native Claude Code verification which lets the SDK explore the
        # codebase with real tools (Read, Grep, Glob, Bash).
        return self._verify_with_native_claude(
            code=code,
            finding=finding,
            attack_vector=attack_vector,
            reasoning=reasoning,
            files_included=files_included,
        )

    def _verify_with_native_claude(
        self,
        code: str,
        finding: str,
        attack_vector: str,
        reasoning: str,
        files_included: list = None,
    ) -> VerificationResult:
        """
        Verify using native Claude Code multi-turn mode.

        Instead of the manual agentic loop with custom tools, this calls
        `claude -p` with multi-turn enabled and lets Claude Code use its
        native tools (Read, Grep, Glob, Bash) to explore the codebase.

        Args:
            code: The code that was assessed
            finding: Stage 1's finding
            attack_vector: Stage 1's attack vector
            reasoning: Stage 1's reasoning
            files_included: Optional list of files in context

        Returns:
            VerificationResult with verdict, exploit path, and explanation
        """
        # run_native_verification imported at module level from .llm_client

            # Wait if we're in a global backoff period
            rate_limiter = get_rate_limiter()
            rate_limiter.wait_if_needed()

            try:
                response = self.client.messages.create(
                    model=VERIFIER_MODEL,
                    max_tokens=MAX_TOKENS_PER_RESPONSE,
                    system=system_prompt,
                    tools=VERIFICATION_TOOLS,
                    messages=messages
                )
            except anthropic.RateLimitError as exc:
                # Report to global rate limiter so all workers back off
                retry_after = float(exc.response.headers.get("retry-after", 0))
                get_rate_limiter().report_rate_limit(retry_after)
                raise

        user_prompt = get_native_claude_verification_prompt(
            code=code,
            finding=finding,
            attack_vector=attack_vector,
            reasoning=reasoning,
            files_included=files_included,
            app_context=self.app_context,
        )
        system_prompt = get_verification_system_prompt(self.app_context)

        try:
            result = run_native_verification(
                prompt=user_prompt,
                system=system_prompt,
                model=VERIFIER_MODEL,
                repo_path=repo_path,
                json_schema=VERIFICATION_JSON_SCHEMA,
                max_budget_usd=0.30,
                timeout=600,
            )
        except (RuntimeError, FileNotFoundError, TimeoutError) as e:
            print(f"[Verify] Native Claude Code verification failed: {e}",
                  file=__import__('sys').stderr)
            return VerificationResult(
                agree=True,
                correct_finding=finding,
                explanation=f"Verification failed: {e}",
                iterations=0,
                total_tokens=0,
            )

        # Track tokens and cost
        input_tokens = result.get("input_tokens", 0)
        output_tokens = result.get("output_tokens", 0)
        total_tokens = input_tokens + output_tokens
        self.tracker.record_call(
            model=VERIFIER_MODEL,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=result.get("cost_usd"),
        )

        # Parse structured JSON from response
        raw_text = result["text"]
        parsed = self._extract_json(raw_text)
        if parsed and "correct_finding" in parsed:
            print(f"[Verify] Parsed JSON: agree={parsed.get('agree')}, "
                  f"correct_finding={parsed.get('correct_finding')}",
                  file=__import__('sys').stderr, flush=True)
            vr = self._parse_finish_result(parsed, finding, 0, total_tokens)
            vr.raw_response = raw_text
            return vr

        # Fallback: try to extract verdict from free-text response
        fallback = self._parse_freetext_verdict(raw_text, finding)
        if fallback:
            print(f"[Verify] Parsed free-text: agree={fallback.get('agree')}, "
                  f"correct_finding={fallback.get('correct_finding')}",
                  file=__import__('sys').stderr, flush=True)
            vr = self._parse_finish_result(fallback, finding, 0, total_tokens)
            vr.raw_response = raw_text
            return vr

        # Final fallback
        print(f"[Verify] Could not parse native Claude Code response: {raw_text[:500]}",
              file=__import__('sys').stderr, flush=True)
        return VerificationResult(
            agree=True,
            correct_finding=finding,
            explanation="Could not parse verification response",
            iterations=0,
            total_tokens=total_tokens,
            raw_response=raw_text,
        )

    def verify_batch(
        self,
        results: list,
        code_by_route: dict,
        progress_callback: Optional[Callable] = None,
        workers: int = 10,
        checkpoint=None,
        restored_callback: Optional[Callable] = None,
    ) -> list:
        """
        Verify a batch of results with consistency cross-check.

        Uses ThreadPoolExecutor for parallel verification when workers > 1.
        Supports checkpoint/resume via the checkpoint parameter.

        Args:
            results: List of Stage 1 results to verify
            code_by_route: Dict mapping route_key to code
            progress_callback: Optional callback(unit_id, detail, unit_elapsed)
                called after each finding is verified.
            workers: Number of parallel workers (default: 10).
            checkpoint: Optional StepCheckpoint instance for resume support.
            restored_callback: Optional callback(count) called after checkpoint
                loading with the number of restored units.

        Returns:
            Updated results with verification and consistency check
        """
        total = len(results)

        # Load checkpoint state
        checkpointed = {}
        if checkpoint is not None:
            checkpointed = checkpoint.load()

        def _cp_is_error(cp_data):
            """A verify checkpoint is errored if verification is missing/empty
            or correct_finding == 'error'."""
            if not cp_data:
                return True
            v = cp_data.get("verification", {})
            if not v:
                return True
            return v.get("correct_finding") == "error"

        # Separate already-done (successful) from to-do (new + errored)
        results_to_verify = []
        _restored_ok = 0
        for r in results:
            key = r.get("unit_id") or r.get("route_key", "unknown")
            cp_data = checkpointed.get(key)
            if cp_data and not _cp_is_error(cp_data):
                # Restore verification data from checkpoint
                if "verification" in cp_data:
                    r["verification"] = cp_data["verification"]
                if "finding" in cp_data:
                    r["finding"] = cp_data["finding"]
                if "verification_note" in cp_data:
                    r["verification_note"] = cp_data["verification_note"]
                _restored_ok += 1
            else:
                # Either no checkpoint, or an errored one — re-verify
                results_to_verify.append(r)

        if _restored_ok:
            print(f"[Verify] Restored {_restored_ok} findings from checkpoints",
                  file=sys.stderr, flush=True)
            if restored_callback:
                restored_callback(_restored_ok)
        errored_retries = len(checkpointed) - _restored_ok
        if errored_retries:
            print(f"[Verify] Retrying {errored_retries} previously errored findings",
                  file=sys.stderr, flush=True)

        # Initialize summary tracking for _summary.json
        _summary_completed = _restored_ok
        _summary_errors = 0
        _summary_error_breakdown = {}
        _summary_input_tokens = 0
        _summary_output_tokens = 0
        _summary_cost_usd = 0.0

        # Sum usage from ALL existing checkpoints (including errored ones
        # — their cost was already spent in a prior run)
        for _key, _cp in checkpointed.items():
            _cp_usage = _cp.get("usage", {})
            _summary_input_tokens += _cp_usage.get("input_tokens", 0)
            _summary_output_tokens += _cp_usage.get("output_tokens", 0)
            _summary_cost_usd += _cp_usage.get("cost_usd", 0.0)

        def _usage_dict():
            return {"input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6)}

        # Inject prior usage into tracker so step_report captures the total
        if _summary_input_tokens or _summary_output_tokens:
            self.tracker.add_prior_usage(
                _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)

        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="in_progress",
                                     usage=_usage_dict())

        def _summary_callback(detail, usage=None):
            """Update summary counters after each unit. Called from main thread."""
            nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
            nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
            if detail == "error":
                _summary_errors += 1
                _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
            else:
                _summary_completed += 1
            if usage:
                _summary_input_tokens += usage.get("input_tokens", 0)
                _summary_output_tokens += usage.get("output_tokens", 0)
                _summary_cost_usd += usage.get("cost_usd", 0.0)
            if checkpoint is not None:
                checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                         _summary_error_breakdown, phase="in_progress",
                                         usage=_usage_dict())

        remaining = len(results_to_verify)
        mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
        print(f"[Verify] Mode: {mode}, {remaining} findings to verify "
              f"({len(checkpointed)} already done)", file=sys.stderr, flush=True)

        if workers <= 1:
            self._verify_batch_sequential(
                results_to_verify, code_by_route, progress_callback, checkpoint,
                summary_callback=_summary_callback)
        else:
            self._verify_batch_parallel(
                results_to_verify, code_by_route, progress_callback, workers, checkpoint,
                summary_callback=_summary_callback)

        # Write final summary with phase="done"
        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="done",
                                     usage=_usage_dict())

        # Step 2: Consistency cross-check (barrier — needs all results)
        results = self._check_consistency(results, code_by_route)

        return results

    def _verify_one(self, result, code_by_route):
        """Verify a single result. Returns (route_key, detail, elapsed, worker, usage).

        Mutates the result dict in-place (each result is unique, no contention).
        """
        route_key = result.get("route_key", "unknown")
        stage1_finding = result.get("finding", "inconclusive")
        worker = threading.current_thread().name

        self.tracker.start_unit_tracking()
        unit_start = time.monotonic()
        detail = ""
        try:
            code = code_by_route.get(route_key, "")
            verification = self.verify_result(
                code=code,
                finding=stage1_finding,
                attack_vector=result.get("attack_vector"),
                reasoning=result.get("reasoning", ""),
                files_included=result.get("files_included", [])
            )

            result["verification"] = verification.to_dict()

            if verification.agree:
                detail = f"agreed:{verification.correct_finding}"
                self._log("info", f"Verification agreed: {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)
            else:
                detail = f"disagreed:{stage1_finding}->{verification.correct_finding}"
                result["finding"] = verification.correct_finding
                result["verification_note"] = f"Changed from {stage1_finding} to {verification.correct_finding}"
                self._log("info", f"Verification disagreed: {stage1_finding} -> {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)

        except Exception as e:
            detail = "error"
            print(f"[Verify] ERROR {route_key}: {type(e).__name__}: {e}", file=sys.stderr, flush=True)

        unit_elapsed = time.monotonic() - unit_start
        usage = self.tracker.get_unit_usage()
        return route_key, detail, unit_elapsed, worker, usage

    def _verify_batch_sequential(self, results, code_by_route, progress_callback,
                                 checkpoint=None, summary_callback=None):
        """Verify all results sequentially."""
        try:
            for i, result in enumerate(results):
                route_key = result.get("route_key", "unknown")
                stage1_finding = result.get("finding", "inconclusive")
                self._log("info", f"Verifying finding {i+1}/{len(results)}",
                          unit_id=route_key, classification=stage1_finding)

                route_key, detail, unit_elapsed, _worker, usage = self._verify_one(result, code_by_route)
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, detail, unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — progress saved to checkpoints",
                  file=sys.stderr, flush=True)

    def _verify_batch_parallel(self, results, code_by_route, progress_callback, workers,
                                checkpoint=None, summary_callback=None):
        """Verify all results in parallel using ThreadPoolExecutor."""
        executor = ThreadPoolExecutor(max_workers=workers)
        future_to_result = {}
        for result in results:
            future = executor.submit(self._verify_one, result, code_by_route)
            future_to_result[future] = result

        try:
            for future in as_completed(future_to_result):
                result = future_to_result[future]
                route_key, detail, unit_elapsed, worker, usage = future.result()
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, f"{detail}  [{worker}]", unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — cancelling pending work...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            print("[Verify] Progress saved to checkpoints",
                  file=sys.stderr, flush=True)
            return
        executor.shutdown(wait=False)

    def _check_consistency(
        self,
        results: list,
        code_by_route: dict
    ) -> list:
        """
        Check for inconsistent verdicts among similar code patterns.

        Groups findings by code pattern similarity and ensures consistent verdicts.

        IMPORTANT: Does NOT override findings that have conclusive exploit path analysis
        showing the path is broken (sink_reached=false, attacker_control=none, or path_broken_at set).
        """
        # Group by vulnerability pattern (simplified: by file and function type)
        pattern_groups = self._group_by_pattern(results)

        inconsistent_groups = []
        for pattern, group in pattern_groups.items():
            if len(group) < 2:
                continue

            verdicts = set(r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group)
            if len(verdicts) > 1:
                inconsistent_groups.append((pattern, group))

        if not inconsistent_groups:
            self._log("info", "Consistency check: All similar patterns have consistent verdicts")
            return results

        # Fix inconsistencies
        for pattern, group in inconsistent_groups:
            verdicts = [r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group]
            self._log("warning", f"Inconsistency detected in pattern: {pattern}",
                      details={"findings": [r.get('route_key') for r in group], "verdicts": verdicts})

            # Run consistency check
            consistency_result = self._resolve_inconsistency(group, code_by_route)

            if consistency_result:
                # Apply consistent verdict, but respect exploit path analysis
                for finding_update in consistency_result.findings_updated:
                    route_key = finding_update.get("route_key")
                    new_verdict = finding_update.get("should_be")

                    for result in results:
                        if result.get("route_key") == route_key:
                            # Check if this result has conclusive exploit path analysis
                            if self._has_conclusive_exploit_path(result):
                                self._log("debug", f"Skipping {route_key}: has conclusive exploit path analysis",
                                          unit_id=route_key)
                                continue

                            old_verdict = result.get("verification", {}).get("correct_finding") or result.get("finding")
                            if old_verdict != new_verdict:
                                result["finding"] = new_verdict
                                if "verification" not in result:
                                    result["verification"] = {}
                                result["verification"]["correct_finding"] = new_verdict
                                result["consistency_update"] = {
                                    "from": old_verdict,
                                    "to": new_verdict,
                                    "reason": finding_update.get("reason"),
                                    "pattern": consistency_result.pattern_identified
                                }
                                self._log("info", f"Consistency update: {old_verdict} -> {new_verdict}",
                                          unit_id=route_key)

        return results

    def _has_conclusive_exploit_path(self, result: dict) -> bool:
        """
        Check if a result has conclusive exploit path analysis that should not be overridden.

        A conclusive exploit path analysis is one where:
        1. The exploit path was analyzed (not just max iterations reached)
        2. The path shows either:
           - sink_reached = false (attacker data doesn't reach the sink)
           - attacker_control_at_sink = "none" (no control at sink)
           - path_broken_at is set (explicit explanation of where path breaks)

        These findings are based on detailed code analysis and should not be
        overridden by superficial pattern matching.
        """
        verification = result.get("verification", {})

        # If max iterations was reached, the analysis is not conclusive
        if verification.get("explanation") == "Max iterations reached":
            return False

        # Check for exploit path analysis
        exploit_path = verification.get("exploit_path")
        if not exploit_path:
            return False

        # Check if the exploit path analysis shows the path is broken
        sink_reached = exploit_path.get("sink_reached", True)
        attacker_control = exploit_path.get("attacker_control_at_sink", "unknown")
        path_broken_at = exploit_path.get("path_broken_at")

        # Conclusive if: path is broken OR sink not reached OR no attacker control
        if not sink_reached:
            return True
        if attacker_control == "none":
            return True
        if path_broken_at:
            return True

        return False

    def _group_by_pattern(self, results: list) -> dict:
        """Group results by code pattern for consistency checking."""
        groups = {}

        for result in results:
            # Extract pattern key from route_key
            route_key = result.get("route_key", "")

            # Group by file and function signature pattern
            # e.g., "pkg/logger/console.go:*Msg.json" groups all json methods
            if ":" in route_key:
                file_part, func_part = route_key.rsplit(":", 1)

                # Normalize function name to find similar patterns
                # e.g., "errorMsg.json" and "infoMsg.json" -> "*Msg.json"
                normalized_func = re.sub(r'^[a-z]+Msg', '*Msg', func_part)
                pattern_key = f"{file_part}:{normalized_func}"
            else:
                pattern_key = route_key

            if pattern_key not in groups:
                groups[pattern_key] = []
            groups[pattern_key].append(result)

        return groups

    def _resolve_inconsistency(
        self,
        group: list,
        code_by_route: dict
    ) -> Optional[ConsistencyCheckResult]:
        """
        Use LLM to resolve inconsistent verdicts for similar code patterns.
        """
        prompt = get_consistency_check_prompt(group, code_by_route)

        try:
            # Wait if we're in a global backoff period
            rate_limiter = get_rate_limiter()
            rate_limiter.wait_if_needed()

            response = self.client.messages.create(
                model=VERIFIER_MODEL,
                max_tokens=MAX_TOKENS_PER_RESPONSE,
                system="You are checking verdict consistency across similar code patterns.",
                messages=[{"role": "user", "content": prompt}]
            )

            self.tracker.record_call(
                model=VERIFIER_MODEL,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                cost_usd=getattr(response, 'cost_usd', None),
            )

            # Parse response
            text = response.content[0].text if response.content else ""
            result = self._parse_json_from_text(text)

            if result:
                return ConsistencyCheckResult(
                    pattern_identified=result.get("pattern_identified", "unknown"),
                    consistent_verdict=result.get("consistent_verdict", "inconclusive"),
                    findings_updated=result.get("findings_to_update", []),
                    explanation=result.get("explanation", "")
                )

        except anthropic.RateLimitError as e:
            # Report to global rate limiter so all workers back off
            retry_after = float(e.response.headers.get("retry-after", 0))
            get_rate_limiter().report_rate_limit(retry_after)
            self._log("error", f"Consistency resolution rate limited", error=str(e))
        except Exception as e:
            self._log("error", f"Consistency resolution failed", error=str(e))

        return None

    def _parse_finish_result(
        self,
        finish_result: dict,
        original_finding: str,
        iterations: int,
        total_tokens: int
    ) -> VerificationResult:
        """Parse the finish tool result into VerificationResult."""
        # Parse exploit path if present
        exploit_path = None
        if "exploit_path" in finish_result and finish_result["exploit_path"]:
            ep = finish_result["exploit_path"]
            exploit_path = ExploitPath(
                entry_point=ep.get("entry_point"),
                data_flow=ep.get("data_flow", []),
                sink_reached=ep.get("sink_reached", False),
                attacker_control_at_sink=ep.get("attacker_control_at_sink", "none"),
                path_broken_at=ep.get("path_broken_at")
            )

        return VerificationResult(
            agree=finish_result.get("agree", True),
            correct_finding=finish_result.get("correct_finding", original_finding),
            explanation=finish_result.get("explanation", ""),
            iterations=iterations,
            total_tokens=total_tokens,
            exploit_path=exploit_path,
            security_weakness=finish_result.get("security_weakness")
        )

    def _parse_json_from_text(self, text: str) -> Optional[dict]:
        """Extract JSON object from text, with LLM correction fallback."""
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

        # Fallback: use LLM to correct malformed JSON
        if text.strip():
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.client)
                corrected = corrector.attempt_correction(text)
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """Extract a JSON object from text without LLM fallback.

        Tries:
        1. Parse the entire text as JSON
        2. Extract JSON from a ```json code block
        3. Find the outermost { ... } pair
        """
        text = text.strip()

        # Try parsing the whole thing
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try extracting from ```json ... ``` code block
        json_block = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_block:
            try:
                return json.loads(json_block.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding outermost braces
        start = text.find('{')
        end = text.rfind('}') + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def _parse_freetext_verdict(text: str, original_finding: str) -> Optional[dict]:
        """Extract a verdict from free-text response when JSON parsing fails.

        Looks for keywords like PROTECTED, SAFE, VULNERABLE in the response
        and constructs a result dict.
        """
        text_lower = text.lower()

        # Determine verdict from common patterns
        correct_finding = None
        agree = None

        # Check for disagree/agree signals
        if "disagree" in text_lower:
            agree = False
        elif "agree" in text_lower:
            agree = True

        # Check for verdict keywords
        for verdict in ["vulnerable", "bypassable", "protected", "safe", "inconclusive"]:
            # Look for patterns like "correct finding is PROTECTED" or "verdict: SAFE"
            patterns = [
                rf'(?:verdict|finding|correct_finding|conclusion)[:\s]*\**{verdict}\**',
                rf'\*\*{verdict.upper()}\*\*',
            ]
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    correct_finding = verdict
                    break
            if correct_finding:
                break

        if not correct_finding:
            return None

        if agree is None:
            agree = correct_finding == original_finding

        # Extract first ~500 chars as explanation
        explanation = text[:500].strip()
        if len(text) > 500:
            explanation += "..."

        return {
            "agree": agree,
            "correct_finding": correct_finding,
            "explanation": explanation,
        }


def _save_verify_checkpoint(checkpoint_path: str, results: list, completed_keys: set,
                            tracker: TokenTracker = None):
    """Save verify checkpoint using atomic writes."""
    from core.utils import atomic_write_json
    # Only save results that have been verified (have verification data)
    verified = []
    for r in results:
        key = r.get("route_key", "unknown")
        if key in completed_keys and "verification" in r:
            verified.append({
                "route_key": key,
                "verification": r["verification"],
                "finding": r.get("finding"),
                "verification_note": r.get("verification_note"),
            })
    data = {
        "completed_keys": list(completed_keys),
        "verified": verified,
    }
    if tracker:
        data["token_usage"] = tracker.get_totals()
    atomic_write_json(checkpoint_path, data)
