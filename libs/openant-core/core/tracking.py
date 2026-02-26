"""
Usage tracking wrapper.

Exposes the existing TokenTracker from utilities/llm_client.py
with scan-level summary and stderr logging.
"""

import sys

from utilities.llm_client import get_global_tracker, reset_global_tracker
from core.schemas import UsageInfo


def reset_tracking():
    """Reset the global token tracker for a new scan."""
    reset_global_tracker()


def get_usage() -> UsageInfo:
    """Get current usage as a UsageInfo dataclass."""
    tracker = get_global_tracker()
    totals = tracker.get_totals()
    return UsageInfo(
        total_calls=totals["total_calls"],
        total_input_tokens=totals["total_input_tokens"],
        total_output_tokens=totals["total_output_tokens"],
        total_tokens=totals["total_tokens"],
        total_cost_usd=totals["total_cost_usd"],
    )


def log_usage(prefix: str = ""):
    """Log current usage summary to stderr."""
    usage = get_usage()
    label = f"{prefix}: " if prefix else ""
    print(
        f"  {label}{usage.total_calls} API calls, "
        f"{usage.total_tokens:,} tokens, "
        f"${usage.total_cost_usd:.4f}",
        file=sys.stderr,
    )
