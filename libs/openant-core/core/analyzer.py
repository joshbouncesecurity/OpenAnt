"""
Analysis wrapper (Stage 1 — detection only).

Wraps the experiment.py analysis logic, accepting file paths instead of
hardcoded dataset names. Reuses the existing analysis functions directly.

Stage 2 verification is handled separately by ``core.verifier``.
"""

import json
import os
import shutil
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from core.schemas import AnalyzeResult, AnalysisMetrics, UsageInfo
from core import tracking
from core.progress import ProgressReporter
from core.utils import atomic_write_json
from utilities.file_io import read_json
from utilities.parallel_executor import run_parallel

# Import existing analysis machinery
from utilities.llm_client import AnthropicClient, get_global_tracker
from utilities.json_corrector import JSONCorrector

# Reuse the core analysis functions from experiment.py
from experiment import (
    analyze_unit,
    parse_response,
    _normalize_result,
)

# Import application context (optional)
try:
    from context.application_context import ApplicationContext, load_context
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    load_context = None


def _recount_metrics(results: list) -> AnalysisMetrics:
    """Recount verdict metrics from the results list.

    This is more reliable than trusting saved metrics, since older runs
    may have missed certain verdict types (e.g. insufficient_context).
    """
    counts = {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "insufficient_context": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }
    for r in results:
        finding = r.get("finding", r.get("verdict", "error").lower())
        if finding in counts:
            counts[finding] += 1
        elif r.get("verdict") == "ERROR":
            counts["errors"] += 1
    return AnalysisMetrics(total=len(results), **counts)


def _save_analyze_checkpoint(checkpoint_path, results, code_by_route, counts, dataset_path, model_id):
    """Save analyze checkpoint using atomic writes."""
    atomic_write_json(checkpoint_path, {
        "results": results,
        "code_by_route": code_by_route,
        "counts": counts,
        "dataset": os.path.basename(dataset_path),
        "model": model_id,
    })


def run_analysis(
    dataset_path: str,
    output_dir: str,
    analyzer_output_path: str | None = None,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    limit: int | None = None,
    model: str = "opus",
    exploitable_only: bool = False,
    checkpoint_path: str | None = None,
    fresh: bool = False,
    skip_errors: bool = False,
    concurrency: int = 4,
) -> AnalyzeResult:
    """Run Stage 1 vulnerability detection on a dataset.

    This is the clean wrapper around experiment.py's run_experiment() logic,
    accepting file paths instead of dataset names. Stage 1 only — for Stage 2
    verification use ``core.verifier.run_verification()``.

    Args:
        dataset_path: Path to dataset.json produced by a parser.
        output_dir: Directory to write results.json.
        analyzer_output_path: Path to analyzer_output.json (unused here,
            accepted for interface compatibility).
        app_context_path: Path to application_context.json (reduces false positives).
        repo_path: Path to the repository (for context correction).
        limit: Max number of units to analyze.
        model: "opus" or "sonnet".
        exploitable_only: If True, only analyze units classified as exploitable
            by the agentic enhancer (requires enhanced dataset).
        checkpoint_path: Path to save/resume checkpoint. Auto-generated if None.
        fresh: If True, delete existing checkpoint and reanalyze all units.
        skip_errors: If True, skip errored units instead of retrying them.
            By default, errored units are automatically retried on re-run.

    Returns:
        AnalyzeResult with results path, metrics, and usage.
    """
    os.makedirs(output_dir, exist_ok=True)

    results_path = os.path.join(output_dir, "results.json")

    # Auto-generate checkpoint path
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

    # Validate flag combinations
    if fresh and skip_errors:
        raise ValueError("Cannot use both --fresh and --skip-errors")

    # Handle fresh mode
    if fresh:
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
    else:
        # Skip-when-already-complete: output exists and no checkpoint means previous run succeeded
        has_checkpoint = os.path.exists(checkpoint_path)
        if os.path.exists(results_path) and not has_checkpoint:
            # Check if there are errored units worth retrying
            experiment = read_json(results_path)
            error_count = sum(
                1 for r in experiment.get("results", [])
                if r.get("verdict") == "ERROR"
            )

            if error_count > 0 and not skip_errors:
                # Copy completed results to checkpoint path so the resume
                # logic re-processes errored units. This works because
                # results.json and the checkpoint format share the same
                # top-level keys ("results", "code_by_route").
                shutil.copy2(results_path, checkpoint_path)
                print(f"[Analyze] Retrying {error_count} errored units from: {results_path}", file=sys.stderr)
            else:
                print(f"[Analyze] Already complete: {results_path}", file=sys.stderr)
                print("[Analyze] Use --fresh to reanalyze all units from scratch.", file=sys.stderr)

                metrics = _recount_metrics(experiment.get("results", []))

                return AnalyzeResult(
                    results_path=results_path,
                    metrics=metrics,
                    usage=UsageInfo(),
                )

    # Reset tracking for this analysis run
    tracking.reset_tracking()

    # Select model
    model_id = "claude-opus-4-6" if model == "opus" else "claude-sonnet-4-20250514"
    print(f"[Analyze] Model: {model_id}", file=sys.stderr)

    # Initialize client
    client = AnthropicClient(model=model_id)

    # Initialize JSON corrector
    json_corrector = JSONCorrector(client)

    # Load application context if provided
    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        print(f"[Analyze] App context: {app_context.application_type}", file=sys.stderr)

    # Load dataset
    print(f"[Analyze] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)

    units = dataset.get("units", [])

    # Optional: filter to exploitable units only (requires enhanced dataset)
    if exploitable_only:
        original_count = len(units)
        units = [
            u for u in units
            if u.get("agent_context", {}).get("security_classification") in ("exploitable", "vulnerable")
        ]
        print(f"[Analyze] Exploitable filter: {original_count} -> {len(units)} units", file=sys.stderr)

    if limit:
        units = units[:limit]

    # --- Stage 1: Detection ---
    results = []
    code_by_route = {}
    counts = {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "insufficient_context": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }

    # Load checkpoint if resuming
    completed_ids = set()
    if checkpoint_path and os.path.exists(checkpoint_path):
        try:
            cp = read_json(checkpoint_path)
            results = cp.get("results", [])
            code_by_route = cp.get("code_by_route", {})
            if not skip_errors:
                # Filter out errored results so they get reprocessed.
                # This zeroes their counts; they'll be recounted after reprocessing.
                results = [r for r in results if r.get("verdict") != "ERROR"]
            completed_ids = {r["unit_id"] for r in results}
            # Recount from checkpoint
            for r in results:
                finding = r.get("finding", "error")
                if finding in counts:
                    counts[finding] += 1
                elif r.get("verdict") == "ERROR":
                    counts["errors"] += 1
            print(f"[Analyze] Resuming: {len(completed_ids)} units already done", file=sys.stderr)
        except (json.JSONDecodeError, OSError):
            # Corrupt checkpoint — start fresh
            print("[Analyze] Corrupt checkpoint, starting fresh", file=sys.stderr)
            results = []
            code_by_route = {}
            completed_ids = set()

    # Set up progress reporter with resumed offset
    tracker = get_global_tracker()
    progress = ProgressReporter("Analyze", len(units), tracker=tracker, completed=len(completed_ids))

    print(f"[Analyze] Analyzing {len(units)} units (concurrency={concurrency})...", file=sys.stderr)

    # Filter to only units that need processing
    pending_units = []
    for i, unit in enumerate(units):
        uid = unit.get("id", f"unit_{i}")
        if uid in completed_ids:
            print(f"  {uid} -> (resumed)", file=sys.stderr)
            continue
        pending_units.append(unit)

    # Per-thread client/corrector to avoid last_call race on shared AnthropicClient.
    # Using threading.local() so each thread creates once and reuses.
    _thread_local = threading.local()

    def _analyze_one(unit):
        """Process a single unit (called from worker thread)."""
        start = time.monotonic()
        if not hasattr(_thread_local, "client"):
            _thread_local.client = AnthropicClient(model=model_id)
            _thread_local.corrector = JSONCorrector(_thread_local.client)
        result = analyze_unit(
            _thread_local.client, unit,
            use_multifile=True,
            json_corrector=_thread_local.corrector,
            app_context=app_context,
        )
        result["_elapsed"] = time.monotonic() - start
        return result

    def _on_complete(unit, result):
        """Called under lock after successful analysis."""
        uid = unit.get("id", "unknown")
        unit_elapsed = result.pop("_elapsed", 0.0)
        result["unit_id"] = uid
        if not result.get("finding") and result.get("verdict"):
            result["finding"] = result["verdict"].lower()

        results.append(result)

        route_key = result.get("route_key", uid)
        code_field = unit.get("code", {})
        if isinstance(code_field, dict):
            code_by_route[route_key] = code_field.get("primary_code", "")
        else:
            code_by_route[route_key] = code_field

        finding = result.get("finding", "error")
        if finding in counts:
            counts[finding] += 1
        elif result.get("verdict") == "ERROR":
            counts["errors"] += 1

        if checkpoint_path:
            _save_analyze_checkpoint(checkpoint_path, results, code_by_route, counts, dataset_path, model_id)
        progress.report(unit_label=uid, detail=finding, unit_elapsed=unit_elapsed)

    def _on_error(unit, exc):
        """Called under lock when analysis raises."""
        uid = unit.get("id", "unknown")
        print(f"  {uid} -> ERROR: {exc}", file=sys.stderr)
        counts["errors"] += 1
        results.append({
            "unit_id": uid,
            "verdict": "ERROR",
            "finding": "error",
            "error": str(exc),
        })
        if checkpoint_path:
            _save_analyze_checkpoint(checkpoint_path, results, code_by_route, counts, dataset_path, model_id)
        progress.report(unit_label=uid, detail="error")

    run_parallel(
        items=pending_units,
        process_fn=_analyze_one,
        concurrency=concurrency,
        on_complete=_on_complete,
        on_error=_on_error,
    )

    progress.finish()

    tracking.log_usage("Stage 1")

    # --- Stage 1 Consistency Check ---
    consistency_corrections = 0
    try:
        from utilities.stage1_consistency import run_stage1_consistency_check
        print("\n[Analyze] Running consistency check...", file=sys.stderr)
        results = run_stage1_consistency_check(results, code_by_route, get_global_tracker())
        # Count corrections
        for r in results:
            if r.get("stage1_consistency_update"):
                consistency_corrections += 1
        if consistency_corrections:
            print(f"  Consistency corrections: {consistency_corrections}", file=sys.stderr)
            # Recount after corrections
            counts = {k: 0 for k in counts}
            for r in results:
                f = r.get("finding", r.get("verdict", "error").lower())
                if f in counts:
                    counts[f] += 1
                elif r.get("verdict") == "ERROR":
                    counts["errors"] += 1
    except ImportError:
        print("[Analyze] Stage 1 consistency check not available, skipping.", file=sys.stderr)
    except Exception as e:
        print(f"[Analyze] Consistency check error (non-fatal): {e}", file=sys.stderr)

    # --- Write results ---
    # Sort by unit_id for deterministic output regardless of concurrency
    results.sort(key=lambda r: r.get("unit_id", ""))

    experiment_result = {
        "dataset": os.path.basename(dataset_path),
        "model": model_id,
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "total": len(units),
            **counts,
        },
        "results": results,
        "code_by_route": code_by_route,
    }

    atomic_write_json(results_path, experiment_result)

    # Clean up checkpoint on success
    if checkpoint_path and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)

    print(f"\n[Analyze] Results written to {results_path}", file=sys.stderr)

    # Build return value
    usage = tracking.get_usage()
    metrics = AnalysisMetrics(
        total=len(units),
        vulnerable=counts["vulnerable"],
        bypassable=counts["bypassable"],
        inconclusive=counts["inconclusive"],
        insufficient_context=counts["insufficient_context"],
        protected=counts["protected"],
        safe=counts["safe"],
        errors=counts["errors"],
    )

    return AnalyzeResult(
        results_path=results_path,
        metrics=metrics,
        usage=usage,
    )
