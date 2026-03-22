"""
Verification wrapper (Stage 2 attacker simulation).

Wraps FindingVerifier to run Stage 2 verification on Stage 1 results.
Only verifies findings classified as vulnerable or bypassable.
"""

import json
import os
import sys
from pathlib import Path

from core.schemas import VerifyResult, UsageInfo
from core import tracking
from core.progress import ProgressReporter
from core.utils import atomic_write_json
from utilities.file_io import read_json

from utilities.llm_client import TokenTracker, get_global_tracker
from utilities.finding_verifier import FindingVerifier
from utilities.agentic_enhancer.repository_index import load_index_from_file

# Import application context (optional)
try:
    from context.application_context import ApplicationContext, load_context
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    load_context = None


def run_verification(
    results_path: str,
    output_dir: str,
    analyzer_output_path: str,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    checkpoint_path: str | None = None,
    fresh: bool = False,
    concurrency: int = 4,
) -> VerifyResult:
    """Run Stage 2 attacker-simulation verification on Stage 1 results.

    Only findings with verdict ``vulnerable`` or ``bypassable`` are verified.
    Results are written to ``results_verified.json`` in *output_dir*.

    Args:
        results_path: Path to ``results.json`` from the analyze step.
        output_dir: Directory to write ``results_verified.json``.
        analyzer_output_path: Path to ``analyzer_output.json`` (required for
            repository index / tool use).
        app_context_path: Optional path to ``application_context.json``.
        repo_path: Optional path to the repository root (passed to index).
        checkpoint_path: Path to save/resume checkpoint. Auto-generated if None.
        fresh: If True, delete existing checkpoint and reverify all findings.

    Returns:
        VerifyResult with paths, counts, and usage info.
    """
    os.makedirs(output_dir, exist_ok=True)

    verified_path = os.path.join(output_dir, "results_verified.json")

    # Auto-generate checkpoint path
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "verify_checkpoint.json")

    # Handle fresh mode
    if fresh:
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
    else:
        # Skip-when-already-complete
        has_checkpoint = os.path.exists(checkpoint_path)
        if os.path.exists(verified_path) and not has_checkpoint:
            print(f"[Verify] Already complete: {verified_path}", file=sys.stderr)
            print("[Verify] Use --fresh to reverify all findings from scratch.", file=sys.stderr)

            verified_data = read_json(verified_path)

            # Count from existing results
            agreed = 0
            disagreed = 0
            confirmed_vulnerabilities = 0
            findings_input = 0
            for r in verified_data.get("results", []):
                # Count vulnerable/bypassable findings as input
                # (matches the fresh verification path's filtering logic)
                finding = r.get("finding", r.get("verdict", "")).lower()
                if finding in ("vulnerable", "bypassable"):
                    findings_input += 1

                verification = r.get("verification")
                if verification is None:
                    continue
                if verification.get("agree", False):
                    agreed += 1
                    if finding in ("vulnerable", "bypassable"):
                        confirmed_vulnerabilities += 1
                else:
                    disagreed += 1

            return VerifyResult(
                verified_results_path=verified_path,
                findings_input=findings_input,
                findings_verified=findings_input,
                agreed=agreed,
                disagreed=disagreed,
                confirmed_vulnerabilities=confirmed_vulnerabilities,
                usage=UsageInfo(),
            )

    # Reset tracking for this verification run
    tracking.reset_tracking()

    # Load Stage 1 results
    print(f"[Verify] Loading results: {results_path}", file=sys.stderr)
    experiment = read_json(results_path)

    all_results = experiment.get("results", [])
    code_by_route = experiment.get("code_by_route", {})

    # Filter to vulnerable/bypassable only
    vulnerable_results = [
        r for r in all_results
        if r.get("finding", r.get("verdict", "").lower()) in ("vulnerable", "bypassable")
    ]

    findings_input = len(vulnerable_results)
    print(f"[Verify] {findings_input} vulnerable/bypassable findings to verify "
          f"(out of {len(all_results)} total)", file=sys.stderr)

    if findings_input == 0:
        # Nothing to verify — write empty verified results
        _write_verified_results(verified_path, experiment, all_results, [])
        return VerifyResult(
            verified_results_path=verified_path,
            findings_input=0,
            findings_verified=0,
            agreed=0,
            disagreed=0,
            confirmed_vulnerabilities=0,
            usage=tracking.get_usage(),
        )

    # Build repository index
    if not analyzer_output_path or not os.path.exists(analyzer_output_path):
        raise FileNotFoundError(
            f"analyzer_output.json is required for Stage 2 verification: "
            f"{analyzer_output_path}"
        )

    print(f"[Verify] Loading repository index...", file=sys.stderr)
    index = load_index_from_file(analyzer_output_path, repo_path)
    print(f"  Index loaded: {len(index.functions)} functions", file=sys.stderr)

    # Load application context if provided
    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        print(f"[Verify] App context: {app_context.application_type}", file=sys.stderr)

    # If no code_by_route in experiment file, build from results
    if not code_by_route:
        code_by_route = _build_code_by_route(all_results)

    # Run Stage 2 verification via verify_batch
    tracker = get_global_tracker()
    verifier = FindingVerifier(
        index=index,
        tracker=tracker,
        verbose=False,
        app_context=app_context,
    )

    print(f"[Verify] Running Stage 2 attacker simulation on {findings_input} findings...",
          file=sys.stderr)

    # Count resumed findings for progress offset
    resumed_count = 0
    if checkpoint_path and os.path.exists(checkpoint_path):
        try:
            cp = read_json(checkpoint_path)
            resumed_count = len(cp.get("completed_keys", []))
        except (json.JSONDecodeError, OSError):
            pass

    # Set up progress reporter
    progress = ProgressReporter("Verify", findings_input, tracker=tracker, completed=resumed_count)

    def _on_finding_done(unit_id: str, detail: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=detail,
            unit_elapsed=unit_elapsed,
        )

    try:
        verified_results = verifier.verify_batch(
            vulnerable_results, code_by_route,
            progress_callback=_on_finding_done,
            checkpoint_path=checkpoint_path,
            concurrency=concurrency,
        )
    except Exception as e:
        print(f"[Verify] ERROR during batch verification: {e}", file=sys.stderr)
        raise

    progress.finish()

    # Count outcomes
    agreed = 0
    disagreed = 0
    confirmed_vulnerabilities = 0

    for r in verified_results:
        verification = r.get("verification", {})
        if verification.get("agree", False):
            agreed += 1
            finding = r.get("finding", "").lower()
            if finding in ("vulnerable", "bypassable"):
                confirmed_vulnerabilities += 1
        else:
            disagreed += 1

    print(f"\n[Verify] Results: {agreed} agreed, {disagreed} disagreed, "
          f"{confirmed_vulnerabilities} confirmed vulnerabilities", file=sys.stderr)

    tracking.log_usage("Stage 2")

    # Merge verified results back into the full result set
    verified_ids = {r.get("unit_id") or r.get("route_key") for r in verified_results}
    merged_results = []
    verified_lookup = {
        (r.get("unit_id") or r.get("route_key")): r for r in verified_results
    }

    for r in all_results:
        key = r.get("unit_id") or r.get("route_key")
        if key in verified_lookup:
            merged_results.append(verified_lookup[key])
        else:
            merged_results.append(r)

    # Write results_verified.json
    _write_verified_results(verified_path, experiment, merged_results, verified_results)

    print(f"[Verify] Verified results written to {verified_path}", file=sys.stderr)

    return VerifyResult(
        verified_results_path=verified_path,
        findings_input=findings_input,
        findings_verified=len(verified_results),
        agreed=agreed,
        disagreed=disagreed,
        confirmed_vulnerabilities=confirmed_vulnerabilities,
        usage=tracking.get_usage(),
    )


def _write_verified_results(
    path: str,
    experiment: dict,
    merged_results: list,
    verified_only: list,
) -> None:
    """Write the verified results file."""
    output = {
        "dataset": experiment.get("dataset", ""),
        "model": experiment.get("model", ""),
        "timestamp": experiment.get("timestamp", ""),
        "verify": True,
        "metrics": experiment.get("metrics", {}),
        "results": merged_results,
        "code_by_route": experiment.get("code_by_route", {}),
        "confirmed_findings": [
            r for r in verified_only
            if r.get("verification", {}).get("agree", False)
            and r.get("finding", "").lower() in ("vulnerable", "bypassable")
        ],
    }

    # Recount metrics after verification
    counts = {
        "vulnerable": 0, "bypassable": 0, "inconclusive": 0,
        "protected": 0, "safe": 0, "errors": 0,
    }
    for r in merged_results:
        finding = r.get("finding", r.get("verdict", "error").lower())
        if finding in counts:
            counts[finding] += 1
        elif r.get("verdict") == "ERROR":
            counts["errors"] += 1

    output["metrics"] = {"total": len(merged_results), **counts}

    atomic_write_json(path, output)


def _build_code_by_route(results: list) -> dict:
    """Build code_by_route from result entries (fallback)."""
    code_by_route = {}
    for r in results:
        route_key = r.get("route_key") or r.get("unit_id", "")
        code = r.get("code", "")
        if isinstance(code, dict):
            code = code.get("primary_code", "")
        if route_key and code:
            code_by_route[route_key] = code
    return code_by_route
