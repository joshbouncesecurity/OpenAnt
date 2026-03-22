"""Tests for Stage 2: analyze/verify per-unit checkpointing."""

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

from core.utils import atomic_write_json
from utilities.file_io import read_json, write_json, open_utf8

# Pre-import modules so we can patch attributes on them
import core.analyzer as analyzer_mod
import core.verifier as verifier_mod
from utilities.finding_verifier import FindingVerifier, _save_verify_checkpoint


# ---------------------------------------------------------------------------
# Fixtures — shared helpers for building test data
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
    return MagicMock(get_totals=lambda: {"total_cost_usd": 0.0})


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
        lambda results, cbr, progress_callback=None, checkpoint_path=None:
        _mock_verify_batch(results, mock_result)
    )

    return [
        patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})),
        patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
            get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)),
        patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier_instance),
    ], mock_verifier_instance


# ---------------------------------------------------------------------------
# Analyze checkpoint tests
# ---------------------------------------------------------------------------


class TestAnalyzeCheckpoint:

    def test_analyze_auto_generates_checkpoint_path(self, tmp_path):
        """Run analysis — checkpoint file is cleaned up on success."""
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
            )

        assert os.path.exists(result.results_path)
        expected_checkpoint = os.path.join(output_dir, "analyze_checkpoint.json")
        assert not os.path.exists(expected_checkpoint)  # cleaned up on success

    def test_analyze_resumes_from_checkpoint(self, tmp_path):
        """Run analysis partway (crash after N units), re-run, verify only remaining units are analyzed."""
        dataset_path = _make_dataset(tmp_path, num_units=5)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Use a mock that raises KeyboardInterrupt after 2 units
        # (KeyboardInterrupt escapes the except Exception handler, simulating a crash)
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

        # First run: succeed for 2 units, then crash
        with pytest.raises(KeyboardInterrupt):
            with patch.object(analyzer_mod, "AnthropicClient"), \
                 patch.object(analyzer_mod, "JSONCorrector"), \
                 patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
                 patch.object(analyzer_mod, "analyze_unit", side_effect=_crash_after_2), \
                 patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
                analyzer_mod.run_analysis(
                    dataset_path=dataset_path,
                    output_dir=output_dir,
                    checkpoint_path=checkpoint_path,
                )

        # Checkpoint should exist with the 2 completed units
        assert os.path.exists(checkpoint_path)
        cp = read_json(checkpoint_path)
        assert len(cp["results"]) == 2

        # Second run: all succeed — should skip the 2 already done
        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result2 = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
            )

        # Only 3 remaining units should have been analyzed
        assert mock_au.call_count == 3

    def test_analyze_fresh_deletes_checkpoint(self, tmp_path):
        """Create checkpoint, call with fresh=True, verify all units reanalyzed."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Create a fake checkpoint
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "results": [{"unit_id": "unit_0", "finding": "safe"}],
            "code_by_route": {},
            "counts": {"safe": 1},
        })

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
                fresh=True,
            )

        # All units should have been processed (checkpoint was deleted)
        assert mock_au.call_count == 3

    def test_analyze_checkpoint_corrupt(self, tmp_path):
        """Corrupt checkpoint file — treated as empty, step starts fresh."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Create corrupt checkpoint
        os.makedirs(output_dir, exist_ok=True)
        with open_utf8(checkpoint_path, "w") as f:
            f.write("{corrupt json!!!}")

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
            )

        # All units should have been processed from scratch
        assert mock_au.call_count == 3

    def test_analyze_checkpoint_cleaned_on_success(self, tmp_path):
        """Run to completion, verify checkpoint file is deleted."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit), \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
            )

        assert os.path.exists(result.results_path)
        assert not os.path.exists(checkpoint_path)

    def test_analyze_skips_when_already_complete(self, tmp_path):
        """Output exists, no checkpoint — returns immediately, no LLM calls."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")

        # First run
        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit) as mock_au, \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}):
            result1 = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
            )

        first_call_count = mock_au.call_count

        # Second run — should skip entirely (output exists, no checkpoint)
        result2 = analyzer_mod.run_analysis(
            dataset_path=dataset_path,
            output_dir=output_dir,
        )

        assert result2.usage.total_cost_usd == 0.0

    def test_analyze_progress_counter_on_resume(self, tmp_path):
        """Verify progress numbering continues from resumed count."""
        dataset_path = _make_dataset(tmp_path, num_units=5)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Create checkpoint with 3 units done
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "results": [
                {"unit_id": "unit_0", "finding": "safe"},
                {"unit_id": "unit_1", "finding": "safe"},
                {"unit_id": "unit_2", "finding": "vulnerable"},
            ],
            "code_by_route": {},
            "counts": {"safe": 2, "vulnerable": 1},
        })

        with patch.object(analyzer_mod, "AnthropicClient"), \
             patch.object(analyzer_mod, "JSONCorrector"), \
             patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()), \
             patch.object(analyzer_mod, "analyze_unit", side_effect=_mock_analyze_unit), \
             patch.dict("sys.modules", {"utilities.stage1_consistency": None}), \
             patch.object(analyzer_mod, "ProgressReporter") as mock_progress_cls:
            mock_progress_cls.return_value = MagicMock()
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
            )

        # ProgressReporter should have been created with completed=3
        mock_progress_cls.assert_called_once()
        _, kwargs = mock_progress_cls.call_args
        assert kwargs["completed"] == 3

    def test_analyze_checkpoint_save_load(self, tmp_path):
        """Save checkpoint, load it, verify completed_ids are populated correctly."""
        from core.analyzer import _save_analyze_checkpoint
        checkpoint_path = str(tmp_path / "analyze_checkpoint.json")

        results = [
            {"unit_id": "unit_0", "finding": "safe"},
            {"unit_id": "unit_1", "finding": "vulnerable"},
        ]
        code_by_route = {"route_0": "code0", "route_1": "code1"}
        counts = {"safe": 1, "vulnerable": 1}

        _save_analyze_checkpoint(checkpoint_path, results, code_by_route, counts, "dataset.json", "opus")

        cp = read_json(checkpoint_path)

        assert len(cp["results"]) == 2
        assert cp["code_by_route"] == code_by_route
        completed_ids = {r["unit_id"] for r in cp["results"]}
        assert completed_ids == {"unit_0", "unit_1"}


# ---------------------------------------------------------------------------
# Verify checkpoint tests
# ---------------------------------------------------------------------------


class TestVerifyCheckpoint:

    def test_verify_auto_generates_checkpoint_path(self, tmp_path):
        """Run verification — verify checkpoint file appears."""
        results_path, ao_path = _make_results(tmp_path, num_results=3, vulnerable_count=1)
        output_dir = str(tmp_path / "output")

        mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
        mock_verifier = MagicMock()
        mock_verifier.verify_batch.side_effect = (
            lambda results, cbr, progress_callback=None, checkpoint_path=None:
            _mock_verify_batch(results, mock_result)
        )

        with patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})), \
             patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
                 get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)), \
             patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier):
            result = verifier_mod.run_verification(
                results_path=results_path,
                output_dir=output_dir,
                analyzer_output_path=ao_path,
            )

        assert os.path.exists(result.verified_results_path)
        # Checkpoint cleaned up by verify_batch mock (which doesn't actually create one)
        expected_checkpoint = os.path.join(output_dir, "verify_checkpoint.json")
        assert not os.path.exists(expected_checkpoint)

    def test_verify_skips_when_already_complete(self, tmp_path):
        """Output exists, no checkpoint — returns immediately, no LLM calls."""
        results_path, ao_path = _make_results(tmp_path, num_results=3, vulnerable_count=1)
        output_dir = str(tmp_path / "output")

        mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
        mock_verifier = MagicMock()
        mock_verifier.verify_batch.side_effect = (
            lambda results, cbr, progress_callback=None, checkpoint_path=None:
            _mock_verify_batch(results, mock_result)
        )

        # First run
        with patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})), \
             patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
                 get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)), \
             patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier):
            result1 = verifier_mod.run_verification(
                results_path=results_path,
                output_dir=output_dir,
                analyzer_output_path=ao_path,
            )

        # Second run — should skip
        result2 = verifier_mod.run_verification(
            results_path=results_path,
            output_dir=output_dir,
            analyzer_output_path=ao_path,
        )

        assert result2.usage.total_cost_usd == 0.0

    def test_verify_fresh_deletes_checkpoint(self, tmp_path):
        """Create checkpoint, call with fresh=True, verify all findings reverified."""
        results_path, ao_path = _make_results(tmp_path, num_results=3, vulnerable_count=2)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "verify_checkpoint.json")

        # Create a fake checkpoint
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "completed_keys": ["src/handler0.js:handler0"],
            "verified": [{
                "route_key": "src/handler0.js:handler0",
                "verification": {"agree": True, "correct_finding": "vulnerable"},
                "finding": "vulnerable",
            }],
        })

        mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
        mock_verifier = MagicMock()
        mock_verifier.verify_batch.side_effect = (
            lambda results, cbr, progress_callback=None, checkpoint_path=None:
            _mock_verify_batch(results, mock_result)
        )

        with patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})), \
             patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
                 get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)), \
             patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier):
            result = verifier_mod.run_verification(
                results_path=results_path,
                output_dir=output_dir,
                analyzer_output_path=ao_path,
                fresh=True,
            )

        # Checkpoint should have been deleted by fresh mode
        assert not os.path.exists(checkpoint_path)

    def test_verify_progress_counter_on_resume(self, tmp_path):
        """Verify progress numbering continues from resumed count."""
        results_path, ao_path = _make_results(tmp_path, num_results=5, vulnerable_count=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "verify_checkpoint.json")

        # Create a checkpoint with 1 finding already verified
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "completed_keys": ["src/handler0.js:handler0"],
            "verified": [{
                "route_key": "src/handler0.js:handler0",
                "verification": {"agree": True, "correct_finding": "vulnerable"},
                "finding": "vulnerable",
            }],
        })

        mock_result = MockVerificationResult(agree=True, correct_finding="vulnerable")
        mock_verifier = MagicMock()
        mock_verifier.verify_batch.side_effect = (
            lambda results, cbr, progress_callback=None, checkpoint_path=None:
            _mock_verify_batch(results, mock_result)
        )

        with patch.object(verifier_mod, "load_index_from_file", return_value=MagicMock(functions={})), \
             patch.object(verifier_mod, "get_global_tracker", return_value=MagicMock(
                 get_totals=lambda: {"total_cost_usd": 0.0}, record_call=lambda **kw: None)), \
             patch.object(verifier_mod, "FindingVerifier", return_value=mock_verifier), \
             patch.object(verifier_mod, "ProgressReporter") as mock_progress_cls:
            mock_progress_cls.return_value = MagicMock()
            result = verifier_mod.run_verification(
                results_path=results_path,
                output_dir=output_dir,
                analyzer_output_path=ao_path,
                checkpoint_path=checkpoint_path,
            )

        # ProgressReporter should have been created with completed=1
        mock_progress_cls.assert_called_once()
        _, kwargs = mock_progress_cls.call_args
        assert kwargs["completed"] == 1


# ---------------------------------------------------------------------------
# FindingVerifier.verify_batch checkpoint tests
# ---------------------------------------------------------------------------


class TestVerifyBatchCheckpoint:

    def test_verify_checkpoint_save_load(self, tmp_path):
        """Save verify checkpoint, load it, verify completed_keys are populated."""
        checkpoint_path = str(tmp_path / "verify_checkpoint.json")
        results = [
            {
                "route_key": "route_0",
                "finding": "vulnerable",
                "verification": {"agree": True, "correct_finding": "vulnerable"},
            },
            {
                "route_key": "route_1",
                "finding": "safe",
                # No verification yet
            },
        ]
        completed_keys = {"route_0"}

        _save_verify_checkpoint(checkpoint_path, results, completed_keys)

        cp = read_json(checkpoint_path)

        assert set(cp["completed_keys"]) == {"route_0"}
        assert len(cp["verified"]) == 1
        assert cp["verified"][0]["route_key"] == "route_0"

    def test_verify_resumes_from_checkpoint(self, tmp_path):
        """Run verify partway, re-run, verify only remaining findings are verified."""
        checkpoint_path = str(tmp_path / "verify_checkpoint.json")

        # Create checkpoint with 1 finding already done
        atomic_write_json(checkpoint_path, {
            "completed_keys": ["route_0"],
            "verified": [{
                "route_key": "route_0",
                "verification": {"agree": True, "correct_finding": "vulnerable"},
                "finding": "vulnerable",
            }],
        })

        results = [
            {"route_key": "route_0", "finding": "vulnerable", "attack_vector": "SQLi", "reasoning": "test", "files_included": []},
            {"route_key": "route_1", "finding": "vulnerable", "attack_vector": "XSS", "reasoning": "test", "files_included": []},
        ]
        code_by_route = {"route_0": "code0", "route_1": "code1"}

        # Create a mock verifier with the real verify_batch method
        verifier = MagicMock(spec=FindingVerifier)
        verifier.verify_result = MagicMock(return_value=MockVerificationResult())
        verifier._check_consistency = lambda r, c: r
        verifier._log = lambda *a, **kw: None

        # Call the unbound method
        FindingVerifier.verify_batch(
            verifier, results, code_by_route,
            checkpoint_path=checkpoint_path,
        )

        # Only route_1 should have been verified (route_0 was resumed)
        assert verifier.verify_result.call_count == 1

    def test_verify_consistency_runs_on_resumed(self, tmp_path):
        """Resume with some findings done, verify consistency cross-check still runs on all results."""
        checkpoint_path = str(tmp_path / "verify_checkpoint.json")

        # Create checkpoint with 1 finding done
        atomic_write_json(checkpoint_path, {
            "completed_keys": ["route_0"],
            "verified": [{
                "route_key": "route_0",
                "verification": {"agree": True, "correct_finding": "vulnerable"},
                "finding": "vulnerable",
            }],
        })

        results = [
            {"route_key": "route_0", "finding": "vulnerable", "attack_vector": "SQLi", "reasoning": "test", "files_included": []},
            {"route_key": "route_1", "finding": "vulnerable", "attack_vector": "XSS", "reasoning": "test", "files_included": []},
        ]
        code_by_route = {"route_0": "code0", "route_1": "code1"}

        consistency_called_with = {}

        def mock_consistency(r, c):
            consistency_called_with["results"] = r
            consistency_called_with["code_by_route"] = c
            return r

        verifier = MagicMock(spec=FindingVerifier)
        verifier.verify_result = MagicMock(return_value=MockVerificationResult())
        verifier._check_consistency = mock_consistency
        verifier._log = lambda *a, **kw: None

        FindingVerifier.verify_batch(
            verifier, results, code_by_route,
            checkpoint_path=checkpoint_path,
        )

        # Consistency check should have received ALL results (including resumed)
        assert len(consistency_called_with["results"]) == 2
