"""Tests for --skip-errors flag: auto-retry errored units on re-run."""

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

from core.utils import atomic_write_json
from utilities.file_io import read_json, write_json

import core.analyzer as analyzer_mod
import core.enhancer as enhancer_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_dataset(tmp_path, num_units=5):
    """Create a minimal dataset for tests."""
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


def _mock_analyze_unit(client, unit, use_multifile=True, json_corrector=None, app_context=None):
    uid = unit.get("id", "unknown")
    return {
        "unit_id": uid,
        "route_key": f"src/{uid}.js:{uid}",
        "finding": "safe",
        "verdict": "SAFE",
        "reasoning": "No vulnerability found",
    }


def _mock_tracker():
    return MagicMock(get_totals=lambda: {"total_cost_usd": 0.0})


def _analyze_patches(mock_au=None):
    """Return context managers for mocking analyze dependencies."""
    side_effect = mock_au or _mock_analyze_unit
    return [
        patch.object(analyzer_mod, "AnthropicClient"),
        patch.object(analyzer_mod, "JSONCorrector"),
        patch.object(analyzer_mod, "get_global_tracker", return_value=_mock_tracker()),
        patch.object(analyzer_mod, "analyze_unit", side_effect=side_effect),
        patch.dict("sys.modules", {"utilities.stage1_consistency": None}),
    ]


# ---------------------------------------------------------------------------
# Enhance: auto-retry errored units
# ---------------------------------------------------------------------------


class TestEnhanceAutoRetryErrors:

    def test_completed_run_with_errors_retries_by_default(self, tmp_path):
        """Completed enhance output with errors -> auto-retries errored units."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_path = str(tmp_path / "dataset_enhanced.json")
        ao_path = str(tmp_path / "analyzer_output.json")
        write_json(ao_path, {"functions": {}, "files": {}})

        # Create a "completed" output with one errored unit
        dataset = read_json(dataset_path)
        for i, unit in enumerate(dataset["units"]):
            if i == 1:
                unit["agent_context"] = {
                    "error": "API timeout",
                    "security_classification": "neutral",
                    "confidence": 0.0,
                }
            else:
                unit["agent_context"] = {
                    "security_classification": "neutral",
                    "confidence": 0.8,
                    "include_functions": [],
                }
        write_json(output_path, dataset)

        # Call enhance_dataset — should copy output to checkpoint and fall through
        # We mock the actual enhancement to avoid LLM calls
        # Lazy imports in enhancer.py require patching at source modules
        mock_enhancer_instance = MagicMock()
        mock_enhancer_instance.enhance_dataset_agentic.return_value = dataset

        with patch("utilities.llm_client.AnthropicClient", return_value=MagicMock()), \
             patch("utilities.llm_client.get_global_tracker", return_value=_mock_tracker()), \
             patch("utilities.context_enhancer.ContextEnhancer", return_value=mock_enhancer_instance), \
             patch("core.progress.ProgressReporter", return_value=MagicMock()), \
             patch("core.utils.atomic_write_json"):
            result = enhancer_mod.enhance_dataset(
                dataset_path=dataset_path,
                output_path=output_path,
                analyzer_output_path=ao_path,
                repo_path=str(tmp_path),
            )

        # Should have called enhance_dataset_agentic (not returned early)
        mock_enhancer_instance.enhance_dataset_agentic.assert_called_once()

        # Verify checkpoint path was passed through
        call_kwargs = mock_enhancer_instance.enhance_dataset_agentic.call_args
        checkpoint_path = str(tmp_path / "dataset_enhanced_checkpoint.json")
        assert call_kwargs.kwargs.get("checkpoint_path") == checkpoint_path

        # Verify the checkpoint file was created (copied from output)
        # and contains the errored unit
        cp_data = read_json(checkpoint_path)
        errored = [u for u in cp_data["units"] if u.get("agent_context", {}).get("error")]
        assert len(errored) == 1
        assert errored[0]["id"] == "unit_1"

    def test_completed_run_with_errors_skips_with_flag(self, tmp_path):
        """Completed output with errors + skip_errors=True -> returns early."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_path = str(tmp_path / "dataset_enhanced.json")

        # Create a "completed" output with one errored unit
        dataset = read_json(dataset_path)
        for i, unit in enumerate(dataset["units"]):
            if i == 1:
                unit["agent_context"] = {
                    "error": "API timeout",
                    "security_classification": "neutral",
                    "confidence": 0.0,
                }
            else:
                unit["agent_context"] = {
                    "security_classification": "neutral",
                    "confidence": 0.8,
                }
        write_json(output_path, dataset)

        result = enhancer_mod.enhance_dataset(
            dataset_path=dataset_path,
            output_path=output_path,
            skip_errors=True,
        )

        # Should return early with cached results (no LLM calls)
        assert result.error_count == 1
        assert result.units_enhanced == 2
        assert result.usage.total_cost_usd == 0.0

    def test_completed_run_no_errors_returns_early(self, tmp_path):
        """Completed output with zero errors -> returns early (no retry needed)."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_path = str(tmp_path / "dataset_enhanced.json")

        # Create a "completed" output with no errors
        dataset = read_json(dataset_path)
        for unit in dataset["units"]:
            unit["agent_context"] = {
                "security_classification": "neutral",
                "confidence": 0.8,
            }
        write_json(output_path, dataset)

        result = enhancer_mod.enhance_dataset(
            dataset_path=dataset_path,
            output_path=output_path,
        )

        # Should return early — no errors to retry
        assert result.error_count == 0
        assert result.usage.total_cost_usd == 0.0

    def test_fresh_and_skip_errors_raises(self, tmp_path):
        """--fresh + --skip-errors -> ValueError."""
        dataset_path = _make_dataset(tmp_path, num_units=1)
        output_path = str(tmp_path / "dataset_enhanced.json")

        with pytest.raises(ValueError, match="Cannot use both"):
            enhancer_mod.enhance_dataset(
                dataset_path=dataset_path,
                output_path=output_path,
                fresh=True,
                skip_errors=True,
            )

    def test_skip_errors_single_shot_raises(self, tmp_path):
        """--skip-errors + single-shot mode -> ValueError."""
        dataset_path = _make_dataset(tmp_path, num_units=1)
        output_path = str(tmp_path / "dataset_enhanced.json")

        with pytest.raises(ValueError, match="only supported in agentic mode"):
            enhancer_mod.enhance_dataset(
                dataset_path=dataset_path,
                output_path=output_path,
                mode="single-shot",
                skip_errors=True,
            )


# ---------------------------------------------------------------------------
# Analyze: auto-retry errored units
# ---------------------------------------------------------------------------


class TestAnalyzeAutoRetryErrors:

    def test_completed_run_with_errors_retries_by_default(self, tmp_path):
        """Completed results.json with errors -> auto-retries errored units."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)

        # Create a "completed" results.json with one errored unit
        results_path = os.path.join(output_dir, "results.json")
        experiment = {
            "dataset": "test.json",
            "model": "claude-opus-4-6",
            "metrics": {"total": 3, "safe": 2, "errors": 1,
                        "vulnerable": 0, "bypassable": 0,
                        "inconclusive": 0, "protected": 0},
            "results": [
                {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_1", "finding": "error", "verdict": "ERROR", "error": "timeout"},
                {"unit_id": "unit_2", "finding": "safe", "verdict": "SAFE"},
            ],
            "code_by_route": {},
        }
        write_json(results_path, experiment)

        patches = _analyze_patches()
        with patches[0], patches[1], patches[2], \
             patches[3] as mock_au, patches[4]:
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
            )

        # Should have retried only the errored unit (unit_1)
        # The checkpoint resume loads 2 successful results, skips them,
        # and processes only unit_1
        assert mock_au.call_count == 1

    def test_completed_run_with_errors_skips_with_flag(self, tmp_path):
        """Completed results with errors + skip_errors=True -> returns early."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)

        results_path = os.path.join(output_dir, "results.json")
        experiment = {
            "dataset": "test.json",
            "model": "claude-opus-4-6",
            "metrics": {"total": 3, "safe": 2, "errors": 1,
                        "vulnerable": 0, "bypassable": 0,
                        "inconclusive": 0, "protected": 0},
            "results": [
                {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_1", "finding": "error", "verdict": "ERROR", "error": "timeout"},
                {"unit_id": "unit_2", "finding": "safe", "verdict": "SAFE"},
            ],
            "code_by_route": {},
        }
        write_json(results_path, experiment)

        result = analyzer_mod.run_analysis(
            dataset_path=dataset_path,
            output_dir=output_dir,
            skip_errors=True,
        )

        # Should return early with cached results
        assert result.metrics.errors == 1
        assert result.usage.total_cost_usd == 0.0

    def test_completed_run_no_errors_returns_early(self, tmp_path):
        """Completed results with zero errors -> returns early."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)

        results_path = os.path.join(output_dir, "results.json")
        experiment = {
            "dataset": "test.json",
            "model": "claude-opus-4-6",
            "metrics": {"total": 3, "safe": 3, "errors": 0,
                        "vulnerable": 0, "bypassable": 0,
                        "inconclusive": 0, "protected": 0},
            "results": [
                {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_1", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_2", "finding": "safe", "verdict": "SAFE"},
            ],
            "code_by_route": {},
        }
        write_json(results_path, experiment)

        result = analyzer_mod.run_analysis(
            dataset_path=dataset_path,
            output_dir=output_dir,
        )

        # Should return early — no errors to retry
        assert result.metrics.errors == 0
        assert result.usage.total_cost_usd == 0.0

    def test_fresh_and_skip_errors_raises(self, tmp_path):
        """--fresh + --skip-errors -> ValueError."""
        dataset_path = _make_dataset(tmp_path, num_units=1)
        output_dir = str(tmp_path / "output")

        with pytest.raises(ValueError, match="Cannot use both"):
            analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                fresh=True,
                skip_errors=True,
            )

    def test_checkpoint_resume_filters_errors_by_default(self, tmp_path):
        """Checkpoint resume excludes errored results from completed_ids."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Create a checkpoint with one errored unit
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "results": [
                {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_1", "finding": "error", "verdict": "ERROR", "error": "timeout"},
            ],
            "code_by_route": {},
            "counts": {"safe": 1, "errors": 1},
        })

        patches = _analyze_patches()
        with patches[0], patches[1], patches[2], \
             patches[3] as mock_au, patches[4]:
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
            )

        # unit_0 is done, unit_1 errored (retried), unit_2 is new
        # So 2 units should be processed
        assert mock_au.call_count == 2

    def test_checkpoint_resume_keeps_errors_with_skip_flag(self, tmp_path):
        """Checkpoint resume with skip_errors keeps errored results in completed_ids."""
        dataset_path = _make_dataset(tmp_path, num_units=3)
        output_dir = str(tmp_path / "output")
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoint.json")

        # Create a checkpoint with one errored unit
        os.makedirs(output_dir, exist_ok=True)
        atomic_write_json(checkpoint_path, {
            "results": [
                {"unit_id": "unit_0", "finding": "safe", "verdict": "SAFE"},
                {"unit_id": "unit_1", "finding": "error", "verdict": "ERROR", "error": "timeout"},
            ],
            "code_by_route": {},
            "counts": {"safe": 1, "errors": 1},
        })

        patches = _analyze_patches()
        with patches[0], patches[1], patches[2], \
             patches[3] as mock_au, patches[4]:
            result = analyzer_mod.run_analysis(
                dataset_path=dataset_path,
                output_dir=output_dir,
                checkpoint_path=checkpoint_path,
                skip_errors=True,
            )

        # unit_0 done, unit_1 errored but SKIPPED, unit_2 is new
        # Only 1 unit should be processed
        assert mock_au.call_count == 1
