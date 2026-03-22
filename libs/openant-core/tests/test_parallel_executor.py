"""Tests for utilities.parallel_executor."""

import threading
import pytest

from utilities.parallel_executor import run_parallel


class TestRunParallelValidation:
    """Input validation tests."""

    def test_concurrency_zero_raises(self):
        with pytest.raises(ValueError, match="concurrency must be >= 1"):
            run_parallel(items=[1], process_fn=lambda x: x, concurrency=0)

    def test_concurrency_negative_raises(self):
        with pytest.raises(ValueError, match="concurrency must be >= 1"):
            run_parallel(items=[1], process_fn=lambda x: x, concurrency=-1)

    def test_empty_items_returns_empty(self):
        results = run_parallel(items=[], process_fn=lambda x: x, concurrency=4)
        assert results == []


class TestSerialPath:
    """Tests for concurrency=1 (serial fast-path)."""

    def test_serial_processes_all_items(self):
        results = run_parallel(
            items=[1, 2, 3],
            process_fn=lambda x: x * 10,
            concurrency=1,
        )
        assert sorted(r for _, r in results) == [10, 20, 30]

    def test_serial_calls_on_complete(self):
        completed = []
        run_parallel(
            items=["a", "b"],
            process_fn=lambda x: x.upper(),
            concurrency=1,
            on_complete=lambda item, result: completed.append((item, result)),
        )
        assert sorted(completed) == [("a", "A"), ("b", "B")]

    def test_serial_calls_on_error(self):
        errors = []

        def _fail(x):
            raise RuntimeError(f"fail-{x}")

        run_parallel(
            items=[1, 2],
            process_fn=_fail,
            concurrency=1,
            on_error=lambda item, exc: errors.append((item, str(exc))),
        )
        assert sorted(errors) == [(1, "fail-1"), (2, "fail-2")]

    def test_serial_error_does_not_stop_processing(self):
        """Errors on individual items don't prevent other items from processing."""
        def _sometimes_fail(x):
            if x == 2:
                raise RuntimeError("boom")
            return x * 10

        results = run_parallel(
            items=[1, 2, 3],
            process_fn=_sometimes_fail,
            concurrency=1,
        )
        assert sorted(r for _, r in results) == [10, 30]


class TestParallelPath:
    """Tests for concurrency > 1 (threaded path)."""

    def test_parallel_processes_all_items(self):
        results = run_parallel(
            items=[1, 2, 3, 4, 5],
            process_fn=lambda x: x * 10,
            concurrency=3,
        )
        assert sorted(r for _, r in results) == [10, 20, 30, 40, 50]

    def test_parallel_calls_on_complete_under_lock(self):
        """on_complete calls are serialized — no interleaving."""
        completed = []
        lock_holders = []

        def _on_complete(item, result):
            # If another thread is in on_complete simultaneously, this would fail
            lock_holders.append(threading.current_thread().ident)
            completed.append(result)
            lock_holders.pop()

        run_parallel(
            items=list(range(20)),
            process_fn=lambda x: x,
            concurrency=4,
            on_complete=_on_complete,
        )
        assert len(completed) == 20

    def test_parallel_calls_on_error(self):
        errors = []

        def _fail(x):
            raise ValueError(f"err-{x}")

        run_parallel(
            items=[1, 2, 3],
            process_fn=_fail,
            concurrency=2,
            on_error=lambda item, exc: errors.append(item),
        )
        assert sorted(errors) == [1, 2, 3]

    def test_parallel_mixed_success_and_error(self):
        """Some items succeed, some fail — both callbacks are invoked."""
        completed = []
        errored = []

        def _fn(x):
            if x % 2 == 0:
                raise RuntimeError("even")
            return x

        run_parallel(
            items=[1, 2, 3, 4, 5],
            process_fn=_fn,
            concurrency=3,
            on_complete=lambda item, result: completed.append(item),
            on_error=lambda item, exc: errored.append(item),
        )
        assert sorted(completed) == [1, 3, 5]
        assert sorted(errored) == [2, 4]

    def test_parallel_results_inside_lock(self):
        """Results list is built under the lock (no race on append)."""
        results = run_parallel(
            items=list(range(50)),
            process_fn=lambda x: x,
            concurrency=8,
        )
        assert len(results) == 50

    def test_parallel_no_callbacks(self):
        """Works fine with no on_complete or on_error."""
        results = run_parallel(
            items=[1, 2, 3],
            process_fn=lambda x: x * 2,
            concurrency=2,
        )
        assert sorted(r for _, r in results) == [2, 4, 6]
