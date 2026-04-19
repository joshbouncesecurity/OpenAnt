"""Tests for checkpoint-based error retry in the pipeline.

``StepCheckpoint`` always retries errored units on resume. These tests
verify that behavior:

- ``StepCheckpoint.load_ids`` excludes errored units by default so they
  get re-processed on the next run.
- ``_run_detection`` skips successfully-checkpointed units but retries
  errored ones.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.checkpoint import StepCheckpoint


# ---------------------------------------------------------------------------
# StepCheckpoint.load_ids — error filtering
# ---------------------------------------------------------------------------


class TestStepCheckpointLoadIds:
    """Verify that load_ids correctly filters errored units."""

    def _save_unit(self, cp: StepCheckpoint, unit_id: str, data: dict):
        """Helper to save a checkpoint unit."""
        cp.save(unit_id, data)

    def test_load_ids_excludes_analyze_errors_by_default(self, tmp_path):
        """Analyze-style errors (verdict=ERROR) are excluded from load_ids."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        self._save_unit(cp, "unit_0", {
            "result": {"verdict": "SAFE", "finding": "safe"},
        })
        self._save_unit(cp, "unit_1", {
            "result": {"verdict": "ERROR", "finding": "error", "error": "timeout"},
        })
        self._save_unit(cp, "unit_2", {
            "result": {"verdict": "VULNERABLE", "finding": "vulnerable"},
        })

        ids = cp.load_ids(skip_errors=True)
        assert ids == {"unit_0", "unit_2"}

    def test_load_ids_includes_errors_when_skip_errors_false(self, tmp_path):
        """When skip_errors=False, errored units are included."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        self._save_unit(cp, "unit_0", {
            "result": {"verdict": "SAFE", "finding": "safe"},
        })
        self._save_unit(cp, "unit_1", {
            "result": {"verdict": "ERROR", "finding": "error"},
        })

        ids = cp.load_ids(skip_errors=False)
        assert ids == {"unit_0", "unit_1"}

    def test_load_ids_excludes_enhance_errors(self, tmp_path):
        """Enhance-style errors (agent_context.error) are excluded."""
        cp = StepCheckpoint("enhance", str(tmp_path))
        self._save_unit(cp, "unit_0", {
            "agent_context": {
                "security_classification": "neutral",
                "confidence": 0.8,
            },
        })
        self._save_unit(cp, "unit_1", {
            "agent_context": {
                "error": "API timeout",
                "security_classification": "neutral",
                "confidence": 0.0,
            },
        })

        ids = cp.load_ids(skip_errors=True)
        assert ids == {"unit_0"}

    def test_load_ids_excludes_dynamic_test_errors(self, tmp_path):
        """Dynamic-test-style errors (status=ERROR) are excluded."""
        cp = StepCheckpoint("dynamic-test", str(tmp_path))
        self._save_unit(cp, "unit_0", {"status": "PASS"})
        self._save_unit(cp, "unit_1", {"status": "ERROR"})

        ids = cp.load_ids(skip_errors=True)
        assert ids == {"unit_0"}

    def test_load_ids_empty_checkpoint(self, tmp_path):
        """Empty checkpoint returns empty set."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        assert cp.load_ids() == set()


# ---------------------------------------------------------------------------
# StepCheckpoint.status — error classification
# ---------------------------------------------------------------------------


class TestStepCheckpointStatus:
    """Verify that status() correctly classifies checkpoint files."""

    def test_status_counts_errors_and_completed(self, tmp_path):
        """Status correctly separates completed vs errored units."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        cp.save("unit_0", {
            "result": {"verdict": "SAFE", "finding": "safe"},
        })
        cp.save("unit_1", {
            "result": {"verdict": "ERROR", "finding": "error", "error": "timeout"},
        })
        cp.save("unit_2", {
            "result": {"verdict": "VULNERABLE", "finding": "vulnerable"},
        })

        status = StepCheckpoint.status(cp.dir)
        assert status["completed"] == 2
        assert status["errors"] == 1
        assert status["total_files"] == 3

    def test_status_empty_dir(self, tmp_path):
        """Status of non-existent checkpoint dir returns zeros."""
        status = StepCheckpoint.status(str(tmp_path / "nonexistent"))
        assert status["completed"] == 0
        assert status["errors"] == 0


# ---------------------------------------------------------------------------
# _run_detection — checkpoint-based error retry
# ---------------------------------------------------------------------------


class TestRunDetectionCheckpointRetry:
    """Verify _run_detection retries errored units from checkpoints."""

    def test_retries_errored_checkpoint_units(self, tmp_path):
        """Errored units in checkpoint are re-processed, successful ones skipped."""
        # Set up a checkpoint with 1 success + 1 error
        cp = StepCheckpoint("Analyze", str(tmp_path))
        cp.save("unit_0", {
            "result": {"unit_id": "unit_0", "verdict": "SAFE", "finding": "safe"},
            "route_key": "unit_0",
            "code_for_route": "code0",
        })
        cp.save("unit_1", {
            "result": {"unit_id": "unit_1", "verdict": "ERROR", "finding": "error",
                       "error": "timeout"},
            "route_key": "unit_1",
            "code_for_route": "",
        })

        units = [
            {"id": "unit_0", "code": {"primary_code": "code0"}},
            {"id": "unit_1", "code": {"primary_code": "code1"}},
            {"id": "unit_2", "code": {"primary_code": "code2"}},
        ]

        call_log = []

        def mock_process(client, unit, index, jc, ac):
            uid = unit["id"]
            call_log.append(uid)
            return {
                "index": index,
                "result": {"unit_id": uid, "verdict": "SAFE", "finding": "safe"},
                "route_key": uid,
                "code_for_route": unit.get("code", {}).get("primary_code", ""),
                "finding": "safe",
                "elapsed": 0.1,
                "error": None,
                "worker": "test",
                "usage": {},
            }

        import core.analyzer as analyzer_mod

        with patch.object(analyzer_mod, "_process_unit", side_effect=mock_process), \
             patch.object(analyzer_mod, "ProgressReporter", return_value=MagicMock()), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=MagicMock()):
            results, code_by_route = analyzer_mod._run_detection(
                units,
                client=MagicMock(),
                json_corrector=MagicMock(),
                app_context=None,
                workers=1,
                checkpoint=cp,
            )

        # unit_0 was successful in checkpoint -> skipped
        # unit_1 errored in checkpoint -> retried
        # unit_2 was never checkpointed -> processed
        assert sorted(call_log) == ["unit_1", "unit_2"]
        # All 3 units should have results
        assert all(r is not None for r in results)

    def test_skips_all_if_no_errors_in_checkpoint(self, tmp_path):
        """All-successful checkpoint: only new units are processed."""
        cp = StepCheckpoint("Analyze", str(tmp_path))
        cp.save("unit_0", {
            "result": {"unit_id": "unit_0", "verdict": "SAFE", "finding": "safe"},
            "route_key": "unit_0",
            "code_for_route": "code0",
        })

        units = [
            {"id": "unit_0", "code": {"primary_code": "code0"}},
        ]

        call_log = []

        def mock_process(client, unit, index, jc, ac):
            call_log.append(unit["id"])
            return {
                "index": index,
                "result": {"unit_id": unit["id"], "verdict": "SAFE", "finding": "safe"},
                "route_key": unit["id"],
                "code_for_route": "",
                "finding": "safe",
                "elapsed": 0.1,
                "error": None,
                "worker": "test",
                "usage": {},
            }

        import core.analyzer as analyzer_mod

        with patch.object(analyzer_mod, "_process_unit", side_effect=mock_process), \
             patch.object(analyzer_mod, "ProgressReporter", return_value=MagicMock()), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=MagicMock()):
            results, code_by_route = analyzer_mod._run_detection(
                units,
                client=MagicMock(),
                json_corrector=MagicMock(),
                app_context=None,
                workers=1,
                checkpoint=cp,
            )

        # unit_0 already done successfully -> nothing to process
        assert call_log == []
        assert results[0] == {"unit_id": "unit_0", "verdict": "SAFE", "finding": "safe"}
