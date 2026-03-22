"""Parallel executor for I/O-bound LLM workloads.

Provides a reusable ``run_parallel()`` helper that wraps
``concurrent.futures.ThreadPoolExecutor`` with:

  - Lock-protected ``on_complete`` / ``on_error`` callbacks (safe for
    checkpoint writes and shared-state mutations).
  - Graceful ``KeyboardInterrupt`` handling (cancels queued futures,
    re-raises promptly).
  - A ``concurrency=1`` fast-path that runs items serially with no
    thread pool overhead.
"""

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional


def run_parallel(
    items: list,
    process_fn: Callable[[Any], Any],
    concurrency: int = 4,
    on_complete: Optional[Callable[[Any, Any], None]] = None,
    on_error: Optional[Callable[[Any, Exception], None]] = None,
) -> list[tuple[Any, Any]]:
    """Process *items* through *process_fn*, up to *concurrency* at a time.

    Args:
        items: Work items to process.
        process_fn: ``(item) -> result``.  Called once per item, potentially
            from a worker thread.
        concurrency: Maximum number of concurrent workers.  ``1`` disables
            threading entirely (serial execution, zero overhead).
        on_complete: ``(item, result) -> None``.  Called under a shared lock
            after *process_fn* returns successfully.  Use this for checkpoint
            writes and shared-state mutations.
        on_error: ``(item, exception) -> None``.  Called under the same lock
            when *process_fn* raises.  Should also checkpoint if needed.

    Returns:
        List of ``(item, result)`` tuples for successful items (in
        completion order).

    Raises:
        KeyboardInterrupt: Re-raised after cancelling queued futures.
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be >= 1, got {concurrency}")

    if not items:
        return []

    # --- Serial fast-path (concurrency == 1) ---
    if concurrency == 1:
        return _run_serial(items, process_fn, on_complete, on_error)

    # --- Parallel path ---
    return _run_threaded(items, process_fn, concurrency, on_complete, on_error)


def _run_serial(items, process_fn, on_complete, on_error):
    """Run items one at a time with no threading."""
    results = []
    for item in items:
        try:
            result = process_fn(item)
        except Exception as exc:
            if on_error:
                on_error(item, exc)
            continue
        if on_complete:
            on_complete(item, result)
        results.append((item, result))
    return results


def _run_threaded(items, process_fn, concurrency, on_complete, on_error):
    """Run items across a thread pool with lock-protected callbacks."""
    lock = threading.Lock()
    results = []

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_item = {
            executor.submit(process_fn, item): item for item in items
        }

        try:
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                except Exception as exc:
                    with lock:
                        if on_error:
                            on_error(item, exc)
                    continue

                with lock:
                    if on_complete:
                        on_complete(item, result)
                    results.append((item, result))

        except KeyboardInterrupt:
            # Cancel queued (not-yet-started) futures; don't wait for
            # in-flight HTTP calls.
            executor.shutdown(wait=False, cancel_futures=True)
            print(
                "\n[parallel] Interrupted — checkpoint is valid, "
                "resume will skip completed units.",
                file=sys.stderr,
            )
            raise

    return results
