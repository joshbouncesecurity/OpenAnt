"""
Context enhancement wrapper.

Wraps utilities/context_enhancer.py, providing a path-based interface
for both agentic and single-shot enhancement modes.

Checkpoints are always enabled for agentic mode. Per-unit progress is saved
to ``{output_dir}/enhance_checkpoints/`` so interrupted runs can resume
automatically. On successful completion the checkpoint dir is removed.
"""

import json
import os
import shutil
import sys

from core.schemas import EnhanceResult, UsageInfo
from core import tracking
from core.progress import ProgressReporter
from utilities.file_io import read_json
from utilities.rate_limiter import configure_rate_limiter


def enhance_dataset(
    dataset_path: str,
    output_path: str,
    analyzer_output_path: str | None = None,
    repo_path: str | None = None,
    mode: str = "agentic",
    checkpoint_path: str | None = None,
    fresh: bool = False,
    skip_errors: bool = False,
    model: str = "sonnet",
    workers: int = 8,
    backoff_seconds: int = 30,
) -> EnhanceResult:
    """Enhance a parsed dataset with security context.

    Args:
        dataset_path: Path to dataset.json from the parse step.
        output_path: Path to write the enhanced dataset.
        analyzer_output_path: Path to analyzer_output.json (required for agentic mode).
        repo_path: Path to the repository (required for agentic mode).
        mode: "agentic" (thorough, tool-use) or "single-shot" (fast, cheaper).
        checkpoint_path: Path to save/resume checkpoint (agentic mode only).
            If None, auto-derived from output_path.
        model: "sonnet" (default, cost-effective).
        workers: Number of parallel workers (default: 8).
        backoff_seconds: Seconds to wait on rate limit before retry (default: 30).

    Returns:
        EnhanceResult with output path, stats, and usage.
    """
    # Configure global rate limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    # Auto-generate checkpoint path next to output file (agentic mode only)
    if checkpoint_path is None and mode == "agentic":
        checkpoint_path = os.path.splitext(output_path)[0] + "_checkpoint.json"

    # Validate flag combinations
    if fresh and skip_errors:
        raise ValueError("Cannot use both --fresh and --skip-errors")
    if skip_errors and mode != "agentic":
        raise ValueError("--skip-errors is only supported in agentic mode")

    # If fresh, delete existing checkpoint and output
    if fresh:
        if checkpoint_path and os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
    else:
        # If output already exists and no checkpoint (i.e. previous run completed),
        # check for errored units to retry.
        has_checkpoint = checkpoint_path and os.path.exists(checkpoint_path)
        if os.path.exists(output_path) and not has_checkpoint:
            # Check if there are errored units worth retrying
            enhanced = read_json(output_path)
            context_key = "agent_context" if mode == "agentic" else "llm_context"
            error_count = sum(
                1 for u in enhanced.get("units", [])
                if u.get(context_key, {}).get("error")
            )

            if error_count > 0 and not skip_errors and checkpoint_path:
                # Copy completed output to checkpoint path so the existing
                # checkpoint resume logic re-processes errored units.
                shutil.copy2(output_path, checkpoint_path)
                print(f"[Enhance] Retrying {error_count} errored units from: {output_path}", file=sys.stderr)
            else:
                print(f"[Enhance] Already complete: {output_path}", file=sys.stderr)
                print("[Enhance] Use --fresh to reprocess all units from scratch.", file=sys.stderr)

                classifications = {}
                for unit in enhanced.get("units", []):
                    ctx = unit.get(context_key, {})
                    if ctx.get("error"):
                        continue
                    cls = ctx.get("security_classification", "unknown")
                    classifications[cls] = classifications.get(cls, 0) + 1

                return EnhanceResult(
                    enhanced_dataset_path=output_path,
                    units_enhanced=len(enhanced.get("units", [])) - error_count,
                    error_count=error_count,
                    classifications=classifications,
                    usage=UsageInfo(),
                )

    from utilities.model_config import MODEL_AUXILIARY, MODEL_PRIMARY
    model_id = MODEL_AUXILIARY if model == "sonnet" else MODEL_PRIMARY
    print(f"[Enhance] Mode: {mode}", file=sys.stderr)
    print(f"[Enhance] Model: {model_id}", file=sys.stderr)

    # Auto-derive checkpoint path for agentic mode
    if mode == "agentic" and checkpoint_path is None:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        checkpoint_path = os.path.join(output_dir, "enhance_checkpoints")

    # Import here to avoid heavy imports at module load
    from utilities.llm_client import AnthropicClient, get_global_tracker
    from utilities.context_enhancer import ContextEnhancer

    tracker = get_global_tracker()
    client = AnthropicClient(model=model_id, tracker=tracker)
    enhancer = ContextEnhancer(client=client, tracker=tracker)

    # Load dataset
    print(f"[Enhance] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)

    units = dataset.get("units", [])
    print(f"[Enhance] Units to enhance: {len(units)}", file=sys.stderr)

    # Count already-resumed units from checkpoint (if any)
    resumed_count = 0
    if checkpoint_path and os.path.exists(checkpoint_path):
        try:
            cp_data = read_json(checkpoint_path)
            for cp_unit in cp_data.get("units", []):
                if cp_unit.get("agent_context"):
                    has_error = cp_unit["agent_context"].get("error")
                    if not has_error or skip_errors:
                        resumed_count += 1
        except (json.JSONDecodeError, OSError):
            pass

    # Set up progress reporter (start counter at resumed count so numbering is correct)
    progress = ProgressReporter("Enhance", len(units), tracker=tracker, completed=resumed_count)

    def _on_unit_done(unit_id: str, classification: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=classification,
            unit_elapsed=unit_elapsed,
        )

    def _on_restored(count: int):
        progress.completed = count

    # Run enhancement
    if mode == "agentic":
        if not analyzer_output_path:
            raise ValueError("Agentic mode requires --analyzer-output")

        enhanced = enhancer.enhance_dataset_agentic(
            dataset=dataset,
            analyzer_output_path=analyzer_output_path,
            repo_path=repo_path,
            verbose=os.getenv("OPENANT_VERBOSE", "").lower() == "true",
            checkpoint_path=checkpoint_path,
            progress_callback=_on_unit_done,
            restored_callback=_on_restored,
            workers=workers,
        )
    elif mode == "single-shot":
        enhanced = enhancer.enhance_dataset(
            dataset,
            progress_callback=_on_unit_done,
            workers=workers,
        )
    else:
        raise ValueError(f"Unknown enhancement mode: {mode}. Use 'agentic' or 'single-shot'.")

    progress.finish()

    # Compute classification distribution and error summary FIRST (before cleanup decision)
    classifications = {}
    error_count = 0
    error_summary = {}
    context_key = "agent_context" if mode == "agentic" else "llm_context"

    for unit in enhanced.get("units", []):
        ctx = unit.get(context_key, {})
        if ctx.get("error"):
            error_count += 1
            err = ctx["error"]
            if isinstance(err, dict):
                err_type = err.get("type", "unknown")
            else:
                err_type = "legacy_string"
            error_summary[err_type] = error_summary.get(err_type, 0) + 1
            continue
        cls = ctx.get("security_classification", "unknown")
        classifications[cls] = classifications.get(cls, 0) + 1

    # Checkpoints are preserved as a permanent artifact alongside results.
    # Final summary (phase="done") is written by context_enhancer.

    # Write enhanced dataset
    from core.utils import atomic_write_json
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    atomic_write_json(output_path, enhanced)

    print(f"[Enhance] Enhanced dataset: {output_path}", file=sys.stderr)
    print(f"[Enhance] Classifications: {classifications}", file=sys.stderr)
    if error_count:
        print(f"[Enhance] Errors: {error_count} ({error_summary})", file=sys.stderr)

    tracking.log_usage("Enhance")

    usage = tracking.get_usage()

    return EnhanceResult(
        enhanced_dataset_path=output_path,
        units_enhanced=len(units) - error_count,
        error_count=error_count,
        error_summary=error_summary,
        classifications=classifications,
        usage=usage,
    )
