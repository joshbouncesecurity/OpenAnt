"""
Analysis wrapper (Stage 1 — detection only).

Wraps the experiment.py analysis logic, accepting file paths instead of
hardcoded dataset names. Reuses the existing analysis functions directly.

Stage 2 verification is handled separately by ``core.verifier``.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from core.schemas import AnalyzeResult, AnalysisMetrics, UsageInfo
from core import tracking

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


def run_analysis(
    dataset_path: str,
    output_dir: str,
    analyzer_output_path: str | None = None,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    limit: int | None = None,
    model: str = "opus",
    exploitable_only: bool = False,
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

    Returns:
        AnalyzeResult with results path, metrics, and usage.
    """
    os.makedirs(output_dir, exist_ok=True)

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
    with open(dataset_path) as f:
        dataset = json.load(f)

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

    print(f"[Analyze] Analyzing {len(units)} units...", file=sys.stderr)

    # --- Stage 1: Detection ---
    results = []
    code_by_route = {}
    counts = {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }

    for i, unit in enumerate(units):
        uid = unit.get("id", f"unit_{i}")
        print(f"  [{i+1}/{len(units)}] {uid}", file=sys.stderr, end="")

        try:
            result = analyze_unit(
                client, unit,
                use_multifile=True,
                json_corrector=json_corrector,
                app_context=app_context,
            )

            # Ensure unit_id is always present
            result["unit_id"] = uid

            # Ensure finding field is always set (may be None after JSON correction)
            if not result.get("finding") and result.get("verdict"):
                result["finding"] = result["verdict"].lower()

            results.append(result)

            # Track code for verify step (code_by_route persisted in results.json)
            route_key = result.get("route_key", uid)
            code_field = unit.get("code", {})
            if isinstance(code_field, dict):
                code_by_route[route_key] = code_field.get("primary_code", "")
            else:
                code_by_route[route_key] = code_field

            # Count verdicts
            finding = result.get("finding", "error")
            if finding in counts:
                counts[finding] += 1
            elif result.get("verdict") == "ERROR":
                counts["errors"] += 1

            print(f" -> {finding}", file=sys.stderr)

        except Exception as e:
            print(f" -> ERROR: {e}", file=sys.stderr)
            counts["errors"] += 1
            results.append({
                "unit_id": uid,
                "verdict": "ERROR",
                "finding": "error",
                "error": str(e),
            })

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
    results_path = os.path.join(output_dir, "results.json")
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

    with open(results_path, "w") as f:
        json.dump(experiment_result, f, indent=2)

    print(f"\n[Analyze] Results written to {results_path}", file=sys.stderr)

    # Build return value
    usage = tracking.get_usage()
    metrics = AnalysisMetrics(
        total=len(units),
        vulnerable=counts["vulnerable"],
        bypassable=counts["bypassable"],
        inconclusive=counts["inconclusive"],
        protected=counts["protected"],
        safe=counts["safe"],
        errors=counts["errors"],
    )

    return AnalyzeResult(
        results_path=results_path,
        metrics=metrics,
        usage=usage,
    )
