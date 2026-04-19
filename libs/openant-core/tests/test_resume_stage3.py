"""Tests for step-level resume helpers used by the scanner.

Tests the lower-level resume utilities: _check_step_completed,
_load_parse_state, _load_analyze_state, _load_verify_state, and
_clean_stale_files.

Note: ScanResult no longer has `resumed_steps` and scan_repository no
longer accepts a `fresh` parameter, so full integration tests for
scan-level resume are not included here.
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.scanner import (
    _check_step_completed,
    _clean_stale_files,
    _load_parse_state,
    _load_analyze_state,
    _load_verify_state,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_json(path, data):
    """Write JSON to a file, creating parent dirs."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _make_step_report(output_dir, step, status="success", summary=None, outputs=None):
    """Create a step report file and return the report dict."""
    report = {
        "step": step,
        "status": status,
        "timestamp": "2026-01-01T00:00:00Z",
        "duration_seconds": 1.0,
        "cost_usd": 0.01,
        "token_usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        "summary": summary or {},
        "inputs": {},
        "outputs": outputs or {},
        "errors": [],
    }
    _write_json(os.path.join(output_dir, f"{step}.report.json"), report)
    return report


def _setup_parse_complete(output_dir, units_count=5, language="python"):
    """Set up a completed parse step with output files."""
    dataset_path = os.path.join(output_dir, "dataset.json")
    ao_path = os.path.join(output_dir, "analyzer_output.json")

    units = [{"id": f"unit_{i}", "code": {"primary_code": f"def f{i}(): pass"}}
             for i in range(units_count)]
    _write_json(dataset_path, {"units": units, "metadata": {}})
    _write_json(ao_path, {"functions": {}, "files": {}})

    _make_step_report(output_dir, "parse",
                      summary={"total_units": units_count, "language": language,
                               "processing_level": "reachable"},
                      outputs={"dataset_path": dataset_path,
                               "analyzer_output_path": ao_path})
    return dataset_path, ao_path


def _setup_analyze_complete(output_dir, units_count=5):
    """Set up a completed analyze step with output files."""
    results_path = os.path.join(output_dir, "results.json")
    results = [{"unit_id": f"unit_{i}", "finding": "safe", "reasoning": "ok"}
               for i in range(units_count)]
    _write_json(results_path, results)

    _make_step_report(output_dir, "analyze",
                      summary={"total_units": units_count,
                               "analyzed": units_count,
                               "verdicts": {"vulnerable": 0, "bypassable": 0,
                                            "inconclusive": 0, "protected": 0,
                                            "safe": units_count, "errors": 0}},
                      outputs={"results_path": results_path})
    return results_path


# ---------------------------------------------------------------------------
# _check_step_completed tests
# ---------------------------------------------------------------------------

class TestCheckStepCompleted:
    def test_no_report(self, tmp_path):
        """No report file -> returns None."""
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_error_status(self, tmp_path):
        """Report with status: error -> returns None."""
        _make_step_report(str(tmp_path), "parse", status="error")
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_missing_output_file(self, tmp_path):
        """Report says success but output file doesn't exist -> returns None."""
        _make_step_report(str(tmp_path), "parse",
                          outputs={"dataset_path": str(tmp_path / "nonexistent.json")})
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_success(self, tmp_path):
        """Valid report + output files exist -> returns report dict."""
        output_dir = str(tmp_path)
        dataset_path = os.path.join(output_dir, "dataset.json")
        _write_json(dataset_path, {"units": []})
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": dataset_path})
        result = _check_step_completed(output_dir, "parse")
        assert result is not None
        assert result["status"] == "success"

    def test_corrupt_report_json(self, tmp_path):
        """Report file with invalid JSON -> returns None."""
        report_path = str(tmp_path / "parse.report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("{invalid json")
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_corrupt_output_json(self, tmp_path):
        """Report says success but output file is invalid JSON -> returns None."""
        output_dir = str(tmp_path)
        dataset_path = os.path.join(output_dir, "dataset.json")
        with open(dataset_path, "w", encoding="utf-8") as f:
            f.write("{truncated")
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": dataset_path})
        assert _check_step_completed(output_dir, "parse") is None

    def test_none_output_value_ignored(self, tmp_path):
        """Output with None value is ignored (not checked)."""
        output_dir = str(tmp_path)
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": None})
        result = _check_step_completed(output_dir, "parse")
        assert result is not None

    def test_non_json_output_checked_for_existence(self, tmp_path):
        """Non-JSON output files are only checked for existence."""
        output_dir = str(tmp_path)
        md_path = os.path.join(output_dir, "report", "SUMMARY_REPORT.md")
        os.makedirs(os.path.dirname(md_path), exist_ok=True)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Report\n")
        _make_step_report(output_dir, "report",
                          outputs={"summary_path": md_path})
        result = _check_step_completed(output_dir, "report")
        assert result is not None

    def test_empty_outputs_section(self, tmp_path):
        """Report with no outputs section -> returns report (vacuously valid)."""
        output_dir = str(tmp_path)
        _make_step_report(output_dir, "parse", outputs={})
        result = _check_step_completed(output_dir, "parse")
        assert result is not None
        assert result["step"] == "parse"


# ---------------------------------------------------------------------------
# _clean_stale_files tests
# ---------------------------------------------------------------------------

class TestCleanStaleFiles:
    def test_deletes_existing_files(self, tmp_path):
        """Stale output files are deleted when listed."""
        output_dir = str(tmp_path)

        stale1 = os.path.join(output_dir, "dataset_enhanced.json")
        stale2 = os.path.join(output_dir, "enhance_checkpoint.json")
        _write_json(stale1, {"stale": True})
        _write_json(stale2, {"stale": True})

        _clean_stale_files(output_dir, ["dataset_enhanced.json", "enhance_checkpoint.json"])

        assert not os.path.exists(stale1)
        assert not os.path.exists(stale2)

    def test_ignores_missing_files(self, tmp_path):
        """No error if the files to clean don't exist."""
        output_dir = str(tmp_path)
        # Should not raise
        _clean_stale_files(output_dir, ["nonexistent.json", "also_missing.json"])

    def test_preserves_unlisted_files(self, tmp_path):
        """Files not in the cleanup list are untouched."""
        output_dir = str(tmp_path)

        keep = os.path.join(output_dir, "dataset.json")
        remove = os.path.join(output_dir, "stale.json")
        _write_json(keep, {"keep": True})
        _write_json(remove, {"remove": True})

        _clean_stale_files(output_dir, ["stale.json"])

        assert os.path.exists(keep)
        assert not os.path.exists(remove)


# ---------------------------------------------------------------------------
# State reconstruction tests
# ---------------------------------------------------------------------------

class TestLoadParseState:
    def test_reconstructs_from_report(self, tmp_path):
        """Reconstructs ParseResult from a step report."""
        output_dir = str(tmp_path)
        _setup_parse_complete(output_dir, units_count=10, language="javascript")
        report = _check_step_completed(output_dir, "parse")
        result = _load_parse_state(report)

        assert result.units_count == 10
        assert result.language == "javascript"
        assert result.processing_level == "reachable"
        assert result.dataset_path.endswith("dataset.json")

    def test_defaults_for_missing_fields(self):
        """Missing summary/output fields get sensible defaults."""
        report = {"summary": {}, "outputs": {}}
        result = _load_parse_state(report)

        assert result.units_count == 0
        assert result.language == "unknown"
        assert result.processing_level == "all"
        assert result.dataset_path == ""


class TestLoadAnalyzeState:
    def test_reconstructs_metrics(self, tmp_path):
        """Reconstructs AnalyzeResult with correct AnalysisMetrics."""
        output_dir = str(tmp_path)
        results_path = os.path.join(output_dir, "results.json")
        _write_json(results_path, [])
        _make_step_report(output_dir, "analyze",
                          summary={"total_units": 20, "analyzed": 18,
                                   "verdicts": {"vulnerable": 3, "bypassable": 1,
                                                "inconclusive": 2, "protected": 5,
                                                "safe": 7, "errors": 2}},
                          outputs={"results_path": results_path})

        report = _check_step_completed(output_dir, "analyze")
        result = _load_analyze_state(report)

        assert result.metrics.total == 20
        assert result.metrics.vulnerable == 3
        assert result.metrics.bypassable == 1
        assert result.metrics.inconclusive == 2
        assert result.metrics.protected == 5
        assert result.metrics.safe == 7
        assert result.metrics.errors == 2

    def test_defaults_for_missing_verdicts(self):
        """Missing verdicts default to zero."""
        report = {"summary": {}, "outputs": {}}
        result = _load_analyze_state(report)

        assert result.metrics.total == 0
        assert result.metrics.vulnerable == 0
        assert result.metrics.safe == 0
        assert result.results_path == ""


class TestLoadVerifyState:
    def test_reconstructs_counts(self, tmp_path):
        """Reconstructs VerifyResult with correct counts."""
        output_dir = str(tmp_path)
        verified_path = os.path.join(output_dir, "results_verified.json")
        _write_json(verified_path, [])
        _make_step_report(output_dir, "verify",
                          summary={"findings_input": 4, "findings_verified": 4,
                                   "agreed": 3, "disagreed": 1,
                                   "confirmed_vulnerabilities": 3},
                          outputs={"verified_results_path": verified_path})

        report = _check_step_completed(output_dir, "verify")
        result = _load_verify_state(report)

        assert result.findings_input == 4
        assert result.findings_verified == 4
        assert result.agreed == 3
        assert result.disagreed == 1
        assert result.confirmed_vulnerabilities == 3

    def test_defaults_for_missing_fields(self):
        """Missing summary fields default to zero."""
        report = {"summary": {}, "outputs": {}}
        result = _load_verify_state(report)

        assert result.findings_input == 0
        assert result.agreed == 0
        assert result.disagreed == 0
        assert result.confirmed_vulnerabilities == 0
        assert result.verified_results_path == ""


# ---------------------------------------------------------------------------
# Step report file round-trip
# ---------------------------------------------------------------------------

class TestStepReportRoundTrip:
    def test_report_written_and_readable(self, tmp_path):
        """A step report written by _make_step_report can be read back."""
        output_dir = str(tmp_path)
        original = _make_step_report(output_dir, "parse",
                                     summary={"total_units": 42},
                                     outputs={"dataset_path": "/tmp/ds.json"})

        report_path = os.path.join(output_dir, "parse.report.json")
        with open(report_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["step"] == "parse"
        assert loaded["status"] == "success"
        assert loaded["summary"]["total_units"] == 42
        assert loaded["outputs"]["dataset_path"] == "/tmp/ds.json"

    def test_multiple_steps_independent(self, tmp_path):
        """Multiple step reports coexist in the same output directory."""
        output_dir = str(tmp_path)
        _make_step_report(output_dir, "parse", summary={"total_units": 10})
        _make_step_report(output_dir, "analyze", summary={"total_units": 10})

        parse_report = _check_step_completed(output_dir, "parse")
        analyze_report = _check_step_completed(output_dir, "analyze")

        assert parse_report is not None
        assert analyze_report is not None
        assert parse_report["step"] == "parse"
        assert analyze_report["step"] == "analyze"
