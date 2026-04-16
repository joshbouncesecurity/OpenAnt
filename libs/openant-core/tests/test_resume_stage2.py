"""Tests for Stage 2: analyze/verify per-unit checkpointing.

Tests the upstream checkpoint system which uses StepCheckpoint from
core.checkpoint with directory-based per-unit checkpoint files.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from dataclasses import dataclass

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.checkpoint import StepCheckpoint
from core.utils import atomic_write_json
from utilities.file_io import read_json, write_json

# Pre-import modules so we can patch attributes on them
import core.analyzer as analyzer_mod
import core.verifier as verifier_mod
from utilities.finding_verifier import FindingVerifier


# ---------------------------------------------------------------------------
# Fixtures -- shared helpers for building test data
# ---------------------------------------------------------------------------


def _make_dataset(tmp_path, num_units=5):
    """Create a minimal dataset for analyze tests."""
    units = []
    for i in range(num_units):
        units.append({
            "id": f"unit_{i}",
            "unit_type": "route_handler",
            "code": {
                "primary_code": f"function handler{i}() {{ return db.query(req.params.id); }}",
                "primary_origin": {
                    "file_path": f"src/handler{i}.js",
                    "function_name": f"handler{i}",
                },
            },
            "metadata": {"direct_calls": [], "direct_callers": []},
        })

    dataset = {"units": units, "metadata": {}}
    dataset_path = str(tmp_path / "dataset.json")
    write_json(dataset_path, dataset)

    return dataset_path


def _make_results(tmp_path, num_results=5, vulnerable_count=2):
    """Create a minimal results.json for verify tests."""
    results = []
    for i in range(num_results):
        finding = "vulnerable" if i < vulnerable_count else "safe"
        results.append({
            "unit_id": f"unit_{i}",
            "route_key": f"src/handler{i}.js:handler{i}",
            "finding": finding,
            "verdict": finding.upper(),
            "attack_vector": "SQL injection via user input" if finding == "vulnerable" else "",
            "reasoning": "User input flows to database query" if finding == "vulnerable" else "No user input",
            "files_included": [f"src/handler{i}.js"],
        })

    code_by_route = {
        r["route_key"]: f"function handler{i}() {{ return 'code'; }}"
        for i, r in enumerate(results)
    }

    experiment = {
        "dataset": "test_dataset.json",
        "model": "claude-opus-4-6",
        "timestamp": "2026-03-19T00:00:00",
        "metrics": {"total": num_results, "vulnerable": vulnerable_count, "safe": num_results - vulnerable_count},
        "results": results,
        "code_by_route": code_by_route,
    }

    results_path = str(tmp_path / "results.json")
    write_json(results_path, experiment)

    # Create a minimal analyzer_output.json
    ao = {"functions": {}, "files": {}}
    ao_path = str(tmp_path / "analyzer_output.json")
    write_json(ao_path, ao)

    return results_path, ao_path


# Mock for analyze_unit that returns a result dict
def _mock_analyze_unit(client, unit, use_multifile=True, json_corrector=None, app_context=None):
    uid = unit.get("id", "unknown")
    return {
        "unit_id": uid,
        "route_key": f"src/{uid}.js:{uid}",
        "finding": "safe",
        "verdict": "SAFE",
        "reasoning": "No vulnerability found",
    }


def _mock_analyze_unit_fail_after(n):
    """Returns a mock that succeeds for first n calls, then raises."""
    call_count = {"count": 0}

    def _mock(client, unit, use_multifile=True, json_corrector=None, app_context=None):
        call_count["count"] += 1
        if call_count["count"] > n:
            raise RuntimeError("Simulated LLM failure")
        uid = unit.get("id", "unknown")
        return {
            "unit_id": uid,
            "route_key": f"src/{uid}.js:{uid}",
            "finding": "vulnerable",
            "verdict": "VULNERABLE",
            "reasoning": "SQL injection found",
        }

    return _mock


# Mock VerificationResult
@dataclass
class MockVerificationResult:
    agree: bool = True
    correct_finding: str = "vulnerable"
    explanation: str = "Confirmed"
    iterations: int = 3
    total_tokens: int = 1000

    def to_dict(self):
        return {
            "agree": self.agree,
            "correct_finding": self.correct_finding,
            "explanation": self.explanation,
            "iterations": self.iterations,
            "total_tokens": self.total_tokens,
        }


def _mock_verify_batch(results, mock_result):
    """Apply mock verification to all results and return them."""
    for r in results:
        r["verification"] = mock_result.to_dict()
    return results


def _mock_tracker():
    """Create a mock tracker."""
    return MagicMock(
        get_totals=lambda: {"total_cost_usd": 0.0},
        start_unit_tracking=lambda: None,
        get_unit_usage=lambda: {},
        add_prior_usage=lambda *a, **kw: None,
        record_call=lambda **kw: None,
    )


def _analyze_patches():
    """Context manager stack for mocking analyze dependencies."""
    return [
        patch.object(analyzer_mod, "AnthropicClient"),
        patch.object(analyzer_mod, "JSONCorrector"),
        patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()),
        patch.dict("sys.modules", {"utilities.stage1_consistency": None}),
    ]


def _verify_patches():
    """Patches for verifier dependencies. Returns mock verify_batch."""
    mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
    mock_verifier_instance = MagicMock()
    mock_verifier_instance.verify_batch.side_effect = (
        lambda results, cbr, **kwargs:
        _mock_verify_batch(results, mock_result)
    )

    return [
        patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})),
        patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
            get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)),
        patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier_instance),
    ], mock_verifier_instance


def _create_analyze_checkpoint(output_dir, unit_results):
    """Create analyze checkpoint directory with per-unit files using StepCheckpoint.

    Args:
        output_dir: The output directory (scan dir).
        unit_results: List of dicts, each with 'unit_id', 'finding', and optionally
            other fields like 'route_key', 'code_for_route'.
    """
    cp = StepCheckpoint("Analyze", output_dir)
    # Override dir to match what run_analysis uses
    cp.dir = os.path.join(output_dir, "analyze_checkpoints")
    for unit in unit_results:
        uid = unit["unit_id"]
        data = {
            "result": {
                "unit_id": uid,
                "finding": unit.get("finding", "safe"),
                "verdict": unit.get("finding", "safe").upper(),
            },
            "route_key": unit.get("route_key", f"src/{uid}.js:{uid}"),
            "code_for_route": unit.get("code_for_route", ""),
        }
        cp.save(uid, data)
    return cp


def _create_verify_checkpoint(output_dir, verified_findings):
    """Create verify checkpoint directory with per-unit files using StepCheckpoint.

    Args:
        output_dir: The output directory (scan dir).
        verified_findings: List of dicts, each with 'unit_id' (or 'route_key'),
            'finding', and 'verification'.
    """
    cp = StepCheckpoint("Verify", output_dir)
    cp.dir = os.path.join(output_dir, "verify_checkpoints")
    for finding in verified_findings:
        uid = finding.get("unit_id") or finding.get("route_key", "unknown")
        data = {
            "finding": finding.get("finding", "vulnerable"),
            "verification": finding.get("verification", {}),
            "route_key": finding.get("route_key", uid),
        }
        cp.save(uid, data)
    return cp


# ---------------------------------------------------------------------------
# Analyze checkpoint tests
# ---------------------------------------------------------------------------


class TestAnalyzeCheckpoint:

    def test_analyze_creates_checkpoint_dir(self, tmp_path):
        """Run analysis -- checkpoint directory is created during processing."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit), \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,
            )

        assert os.path.exists(result.results_path)
        # Checkpoint dir should exist with phase="done" summary
        checkpoint_dir = os.path.join(output_dir, "analyze_checkpoints")
        assert os.path.isdir(checkpoint_dir)

    def test_analyze_resumes_from_checkpoint(self, tmp_path):
        """Run analysis partway (interrupt after N units), re-run, verify only remaining units are analyzed."""
        dataset_path = _make_dataset(tmp_path, num_units=5)
        output_dir = str(tmp_path / "output")

        # Use a mock that raises KeyboardInterrupt after 2 units
        def _crash_after_2(client, unit, use_multifile=True, json_corrector=None, app_context=None):
            _crash_after_2.count = getattr(_crash_after_2, "count", 0) + 1
            if _crash_after_2.count > 2:
                raise KeyboardInterrupt("Simulated crash")
            uid = unit.get("id", "unknown")
            return {
                "unit_id": uid,
                "route_key": f"src/{uid}.js:{uid}",
                "finding": "vulnerable",
                "verdict": "VULNERABLE",
                "reasoning": "SQL injection found",
            }

        # First run: succeed for 2 units, then interrupt (caught gracefully by upstream)
        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_crash_after_2), \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result1 = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,  # serial to guarantee exact crash point
            )

        # Checkpoint directory should exist with the 2 completed units
        checkpoint_dir = os.path.join(output_dir, "analyze_checkpoints")
        assert os.path.isdir(checkpoint_dir)
        cp = StepCheckpoint("Analyze", output_dir)
        cp.dir = checkpoint_dir
        loaded = cp.load()
        assert len(loaded) == 2

        # Second run: all succeed -- should skip the 2 already done
        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result2 = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,
            )

        # Only 3 remaining units should have been analyzed
        assert mock_au.call_count == 3

    def test_analyze_checkpoint_corrupt_unit_file(self, tmp_path):
        """Corrupt checkpoint file in checkpoint dir -- treated as missing, unit is reprocessed."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_dir = os.path.join(output_dir, "analyze_checkpoints")

        # Create checkpoint dir with one corrupt file
        os.makedirs(checkpoint_dir, exist_ok=True)
        corrupt_path = os.path.join(checkpoint_dir, "corrupt_unit.json")
        with open(corrupt_path, "w") as f:
            f.write("{corrupt json!!!}")

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,
            )

        # All 3 units should have been processed (corrupt file is ignored by StepCheckpoint.load)
        assert mock_au.call_count == 3

    def test_analyze_checkpoint_preserves_on_success(self, tmp_path):
        """Run to completion, verify checkpoint directory is preserved with phase=done summary."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit), \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,
            )

        assert os.path.exists(result.results_path)
        # Upstream preserves checkpoints as permanent artifacts
        checkpoint_dir = os.path.join(output_dir, "analyze_checkpoints")
        assert os.path.isdir(checkpoint_dir)
        # Summary should show phase=done
        summary = StepCheckpoint.read_summary(checkpoint_dir)
        assert summary is not None
        assert summary["phase"] == "done"

    def test_analyze_resumes_with_pre_seeded_checkpoint(self, tmp_path):
        """Pre-seed checkpoint directory with completed units, verify they are skipped."""
        dataset_path = _make_dataset(tmp_path, num_units=5)
        output_dir = str(tmp_path / "output")

        # Create checkpoint with 3 units done
        _create_analyze_checkpoint(output_dir, [
            {"unit_id": "unit_0", "finding": "safe"},
            {"unit_id": "unit_1", "finding": "safe"},
            {"unit_id": "unit_2", "finding": "vulnerable"},
        ])

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                workers=1,
            )

        # Only 2 remaining units should have been analyzed
        assert mock_au.call_count == 2


# ---------------------------------------------------------------------------
# StepCheckpoint unit tests
# ---------------------------------------------------------------------------


class TestStepCheckpointUnit:

    def test_save_and_load(self, tmp_path):
        """Save checkpoint data for a unit, load it back, verify round-trip."""
        cp = StepCheckpoint("analyze", str(tmp_path))

        cp.save("unit_0", {
            "result": {"unit_id": "unit_0", "finding": "safe"},
            "route_key": "route_0",
            "code_for_route": "code0",
        })
        cp.save("unit_1", {
            "result": {"unit_id": "unit_1", "finding": "vulnerable"},
            "route_key": "route_1",
            "code_for_route": "code1",
        })

        loaded = cp.load()
        assert len(loaded) == 2
        assert "unit_0" in loaded
        assert "unit_1" in loaded
        assert loaded["unit_0"]["result"]["finding"] == "safe"
        assert loaded["unit_1"]["result"]["finding"] == "vulnerable"

    def test_load_ids(self, tmp_path):
        """load_ids returns set of completed unit IDs."""
        cp = StepCheckpoint("analyze", str(tmp_path))

        cp.save("unit_0", {
            "result": {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
        })
        cp.save("unit_1", {
            "result": {"unit_id": "unit_1", "finding": "error", "verdict": "ERROR"},
        })

        # With skip_errors=True (default), errored units are excluded
        ids = cp.load_ids()
        assert ids == {"unit_0"}

        # With skip_errors=False, all units are included
        ids_all = cp.load_ids(skip_errors=False)
        assert ids_all == {"unit_0", "unit_1"}

    def test_exists_and_count(self, tmp_path):
        """exists and count reflect checkpoint state."""
        cp = StepCheckpoint("analyze", str(tmp_path))

        assert not cp.exists
        assert cp.count() == 0

        cp.save("unit_0", {"result": {"finding": "safe"}})
        assert cp.exists
        assert cp.count() == 1

        cp.save("unit_1", {"result": {"finding": "vulnerable"}})
        assert cp.count() == 2

    def test_cleanup(self, tmp_path):
        """cleanup removes the checkpoint directory."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        cp.save("unit_0", {"result": {"finding": "safe"}})
        assert os.path.isdir(cp.dir)

        cp.cleanup()
        assert not os.path.isdir(cp.dir)

    def test_write_and_read_summary(self, tmp_path):
        """write_summary and read_summary round-trip correctly."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        cp.write_summary(
            total_units=10,
            completed=5,
            errors=1,
            error_breakdown={"api": 1},
            phase="in_progress",
        )

        summary = StepCheckpoint.read_summary(cp.dir)
        assert summary is not None
        assert summary["step"] == "analyze"
        assert summary["phase"] == "in_progress"
        assert summary["total_units"] == 10
        assert summary["completed"] == 5
        assert summary["errors"] == 1

    def test_corrupt_file_skipped_on_load(self, tmp_path):
        """Corrupt JSON files in checkpoint dir are silently skipped."""
        cp = StepCheckpoint("analyze", str(tmp_path))
        cp.ensure_dir()

        # Write a valid checkpoint
        cp.save("unit_0", {"result": {"finding": "safe"}})

        # Write a corrupt file
        corrupt_path = os.path.join(cp.dir, "corrupt.json")
        with open(corrupt_path, "w") as f:
            f.write("{invalid json!!!")

        loaded = cp.load()
        assert len(loaded) == 1
        assert "unit_0" in loaded


# ---------------------------------------------------------------------------
# Verify checkpoint tests
# ---------------------------------------------------------------------------


class TestVerifyCheckpoint:

    def test_verify_creates_output(self, tmp_path):
        """Run verification -- verified output file is created."""
        results_path, ao_path = _make_results(tmp_path, num_results=3, vulnerable_count=1)
        output_dir = str(tmp_path / "output")

        mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
        mock_verifier = MagicMock()
        mock_verifier.verify_batch.side_effect = (
            lambda results, cbr, **kwargs:
            _mock_verify_batch(results, mock_result)
        )

        with patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})), \
             patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
                 get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None,
                 add_prior_usage=lambda *a, **kw: None)), \
             patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier):
            result = verifier_mod.run_verification(
                results_path=results_path,
                output_dir=output_dir,
                analyzer_output_path=ao_path,
                workers=1,
            )

        assert os.path.exists(result.verified_results_path)

    def test_verify_no_vulnerable_skips_llm(self, tmp_path):
        """When no vulnerable findings exist, verification returns immediately with no LLM calls."""
        results_path, ao_path = _make_results(tmp_path, num_results=3, vulnerable_count=0)
        output_dir = str(tmp_path / "output")

        # No vulnerable findings -- should skip verification entirely
        result = verifier_mod.run_verification(
            results_path=results_path,
            output_dir=output_dir,
            analyzer_output_path=ao_path,
            workers=1,
        )

        assert result.findings_input == 0
        assert result.findings_verified == 0
        assert os.path.exists(result.verified_results_path)


# ---------------------------------------------------------------------------
# FindingVerifier.verify_batch checkpoint tests
# ---------------------------------------------------------------------------


class TestVerifyBatchCheckpoint:

    def test_verify_resumes_from_checkpoint(self, tmp_path):
        """Run verify with pre-seeded checkpoint, verify only remaining findings are verified."""
        output_dir = str(tmp_path / "output")

        # Create checkpoint with 1 finding already done
        _create_verify_checkpoint(output_dir, [{
            "unit_id": "unit_0",
            "route_key": "route_0",
            "finding": "vulnerable",
            "verification": {"agree": True, "correct_finding": "vulnerable"},
        }])

        checkpoint = StepCheckpoint("Verify", output_dir)
        checkpoint.dir = os.path.join(output_dir, "verify_checkpoints")

        results = [
            {"unit_id": "unit_0", "route_key": "route_0", "finding": "vulnerable",
             "attack_vector": "SQLi", "reasoning": "test", "files_included": []},
            {"unit_id": "unit_1", "route_key": "route_1", "finding": "vulnerable",
             "attack_vector": "XSS", "reasoning": "test", "files_included": []},
        ]
        code_by_route = {"route_0": "code0", "route_1": "code1"}

        # Create a mock verifier with the real verify_batch method.
        # We must bind the real _verify_batch_sequential and _verify_one methods
        # so that verify_batch (called as unbound) dispatches correctly.
        verifier = MagicMock()
        verifier.verify_result = MagicMock(return_value=MockVerificationResult())
        verifier._check_consistency = lambda r, c: r
        verifier._log = lambda *a, **kw: None
        verifier.verbose = False
        verifier.output_dir = None
        verifier.tracker = MagicMock(
            get_totals=lambda: {"total_cost_usd": 0.0},
            add_prior_usage=lambda *a, **kw: None,
            start_unit_tracking=lambda: None,
            get_unit_usage=lambda: {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        )
        # Bind the real methods so the unbound verify_batch call works
        verifier._verify_one = lambda result, cbr: FindingVerifier._verify_one(verifier, result, cbr)
        verifier._verify_batch_sequential = (
            lambda results, cbr, progress_callback=None, checkpoint=None, summary_callback=None:
            FindingVerifier._verify_batch_sequential(
                verifier, results, cbr, progress_callback, checkpoint,
                summary_callback=summary_callback)
        )

        # Call the unbound method with checkpoint
        FindingVerifier.verify_batch(
            verifier, results, code_by_route,
            checkpoint=checkpoint,
            workers=1,
        )

        # Only unit_1 should have been verified (unit_0 was resumed from checkpoint)
        assert verifier.verify_result.call_count == 1

    def test_verify_consistency_runs_on_resumed(self, tmp_path):
        """Resume with some findings done, verify consistency cross-check still runs on all results."""
        output_dir = str(tmp_path / "output")

        # Create checkpoint with 1 finding done
        _create_verify_checkpoint(output_dir, [{
            "unit_id": "unit_0",
            "route_key": "route_0",
            "finding": "vulnerable",
            "verification": {"agree": True, "correct_finding": "vulnerable"},
        }])

        checkpoint = StepCheckpoint("Verify", output_dir)
        checkpoint.dir = os.path.join(output_dir, "verify_checkpoints")

        results = [
            {"unit_id": "unit_0", "route_key": "route_0", "finding": "vulnerable",
             "attack_vector": "SQLi", "reasoning": "test", "files_included": []},
            {"unit_id": "unit_1", "route_key": "route_1", "finding": "vulnerable",
             "attack_vector": "XSS", "reasoning": "test", "files_included": []},
        ]
        code_by_route = {"route_0": "code0", "route_1": "code1"}

        consistency_called_with = {}

        def mock_consistency(r, c):
            consistency_called_with["results"] = r
            consistency_called_with["code_by_route"] = c
            return r

        verifier = MagicMock()
        verifier.verify_result = MagicMock(return_value=MockVerificationResult())
        verifier._check_consistency = mock_consistency
        verifier._log = lambda *a, **kw: None
        verifier.verbose = False
        verifier.output_dir = None
        verifier.tracker = MagicMock(
            get_totals=lambda: {"total_cost_usd": 0.0},
            add_prior_usage=lambda *a, **kw: None,
            start_unit_tracking=lambda: None,
            get_unit_usage=lambda: {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
        )
        # Bind the real methods so the unbound verify_batch call works
        verifier._verify_one = lambda result, cbr: FindingVerifier._verify_one(verifier, result, cbr)
        verifier._verify_batch_sequential = (
            lambda results, cbr, progress_callback=None, checkpoint=None, summary_callback=None:
            FindingVerifier._verify_batch_sequential(
                verifier, results, cbr, progress_callback, checkpoint,
                summary_callback=summary_callback)
        )

        FindingVerifier.verify_batch(
            verifier, results, code_by_route,
            checkpoint=checkpoint,
            workers=1,
        )

        # Consistency check should have received ALL results (including resumed)
        assert len(consistency_called_with["results"]) == 2
