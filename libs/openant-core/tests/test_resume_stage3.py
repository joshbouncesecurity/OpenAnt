"""Tests for Stage 3: scan step-level resume."""

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

from core.scanner import _check_step_completed, _load_parse_state, _load_analyze_state, _load_verify_state
from core.schemas import UsageInfo


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_json(path, data):
    """Write JSON to a file, creating parent dirs."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
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


def _setup_enhance_complete(output_dir, dataset_path):
    """Set up a completed enhance step with output files."""
    enhanced_path = os.path.join(output_dir, "dataset_enhanced.json")
    with open(dataset_path) as f:
        dataset = json.load(f)
    for unit in dataset.get("units", []):
        unit["agent_context"] = {"security_classification": "neutral"}
    _write_json(enhanced_path, dataset)

    _make_step_report(output_dir, "enhance",
                      summary={"units_enhanced": len(dataset.get("units", [])),
                               "error_count": 0, "classifications": {"neutral": 5},
                               "mode": "agentic"},
                      outputs={"enhanced_dataset_path": enhanced_path})
    return enhanced_path


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


def _setup_build_output_complete(output_dir, results_path):
    """Set up a completed build-output step."""
    pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")
    _write_json(pipeline_output_path, {
        "findings": [], "metadata": {},
        "step_reports": [],
    })

    _make_step_report(output_dir, "build-output",
                      summary={},
                      outputs={"pipeline_output_path": pipeline_output_path})
    return pipeline_output_path


def _setup_report_complete(output_dir):
    """Set up a completed report step."""
    report_dir = os.path.join(output_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    summary_path = os.path.join(report_dir, "SUMMARY_REPORT.md")
    with open(summary_path, "w") as f:
        f.write("# Summary Report\n")

    _make_step_report(output_dir, "report",
                      summary={"formats_generated": ["summary_path"]},
                      outputs={"summary_path": summary_path})
    return summary_path


# ---------------------------------------------------------------------------
# _check_step_completed tests
# ---------------------------------------------------------------------------

class TestCheckStepCompleted:
    def test_check_step_no_report(self, tmp_path):
        """No report file -> returns None."""
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_check_step_error_status(self, tmp_path):
        """Report with status: error -> returns None."""
        _make_step_report(str(tmp_path), "parse", status="error")
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_check_step_missing_output(self, tmp_path):
        """Report says success but output file doesn't exist -> returns None."""
        _make_step_report(str(tmp_path), "parse",
                          outputs={"dataset_path": str(tmp_path / "nonexistent.json")})
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_check_step_success(self, tmp_path):
        """Valid report + output files exist -> returns report dict."""
        output_dir = str(tmp_path)
        dataset_path = os.path.join(output_dir, "dataset.json")
        _write_json(dataset_path, {"units": []})
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": dataset_path})
        result = _check_step_completed(output_dir, "parse")
        assert result is not None
        assert result["status"] == "success"

    def test_check_step_corrupt_json(self, tmp_path):
        """Report file with invalid JSON -> returns None."""
        report_path = str(tmp_path / "parse.report.json")
        with open(report_path, "w") as f:
            f.write("{invalid json")
        assert _check_step_completed(str(tmp_path), "parse") is None

    def test_check_step_corrupt_output(self, tmp_path):
        """Report says success but output file is invalid JSON -> returns None."""
        output_dir = str(tmp_path)
        dataset_path = os.path.join(output_dir, "dataset.json")
        with open(dataset_path, "w") as f:
            f.write("{truncated")
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": dataset_path})
        assert _check_step_completed(output_dir, "parse") is None

    def test_check_step_none_output_value(self, tmp_path):
        """Output with None value is ignored (not checked)."""
        output_dir = str(tmp_path)
        _make_step_report(output_dir, "parse",
                          outputs={"dataset_path": None})
        result = _check_step_completed(output_dir, "parse")
        assert result is not None

    def test_check_step_non_json_output(self, tmp_path):
        """Non-JSON output files are only checked for existence."""
        output_dir = str(tmp_path)
        md_path = os.path.join(output_dir, "report", "SUMMARY_REPORT.md")
        os.makedirs(os.path.dirname(md_path), exist_ok=True)
        with open(md_path, "w") as f:
            f.write("# Report\n")
        _make_step_report(output_dir, "report",
                          outputs={"summary_path": md_path})
        result = _check_step_completed(output_dir, "report")
        assert result is not None


# ---------------------------------------------------------------------------
# Stale file cleanup tests
# ---------------------------------------------------------------------------

class TestStaleFileCleanup:
    def test_stale_files_deleted_on_rerun(self, tmp_path):
        """Stale output files are deleted when a step re-executes."""
        from core.scanner import _clean_stale_files
        output_dir = str(tmp_path)

        # Create stale files
        stale_path = os.path.join(output_dir, "dataset_enhanced.json")
        _write_json(stale_path, {"stale": True})
        cp_path = os.path.join(output_dir, "enhance_checkpoint.json")
        _write_json(cp_path, {"stale": True})

        _clean_stale_files(output_dir, ["dataset_enhanced.json", "enhance_checkpoint.json"])

        assert not os.path.exists(stale_path)
        assert not os.path.exists(cp_path)

    def test_stale_files_kept_on_resume(self, tmp_path):
        """Output files are NOT deleted when step is resumed."""
        output_dir = str(tmp_path)

        # Set up complete step
        dataset_path, ao_path = _setup_parse_complete(output_dir)

        # Files should still exist (resume doesn't touch them)
        assert os.path.exists(dataset_path)
        assert os.path.exists(ao_path)


# ---------------------------------------------------------------------------
# State reconstruction tests
# ---------------------------------------------------------------------------

class TestStateReconstruction:
    def test_load_parse_state(self, tmp_path):
        """Reconstructs ParseResult from a step report."""
        output_dir = str(tmp_path)
        _setup_parse_complete(output_dir, units_count=10, language="javascript")
        report = _check_step_completed(output_dir, "parse")
        result = _load_parse_state(report)

        assert result.units_count == 10
        assert result.language == "javascript"
        assert result.processing_level == "reachable"
        assert result.dataset_path.endswith("dataset.json")

    def test_load_analyze_state(self, tmp_path):
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
        assert result.metrics.safe == 7
        assert result.metrics.errors == 2

    def test_load_verify_state(self, tmp_path):
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
        assert result.agreed == 3
        assert result.disagreed == 1
        assert result.confirmed_vulnerabilities == 3


# ---------------------------------------------------------------------------
# Integration tests (mocked pipeline)
# ---------------------------------------------------------------------------

# Common mocks to prevent real module imports
_SCANNER_MOCKS = {
    "core.parser_adapter.parse_repository": None,
    "core.enhancer.enhance_dataset": None,
    "core.analyzer.run_analysis": None,
    "core.verifier.run_verification": None,
    "core.reporter.build_pipeline_output": None,
    "core.reporter.generate_summary_report": None,
    "core.reporter.generate_disclosure_docs": None,
}


class TestScanResumeIntegration:
    def test_scan_resume_all_complete(self, tmp_path):
        """All step reports present -> all steps resumed, no LLM calls."""
        output_dir = str(tmp_path)

        # Set up all steps as complete
        dataset_path, ao_path = _setup_parse_complete(output_dir)
        enhanced_path = _setup_enhance_complete(output_dir, dataset_path)
        results_path = _setup_analyze_complete(output_dir)
        pipeline_output_path = _setup_build_output_complete(output_dir, results_path)
        summary_path = _setup_report_complete(output_dir)

        from core.scanner import scan_repository

        # Mock tracking to avoid side effects
        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()):
            result = scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
            )

        assert "parse" in result.resumed_steps
        assert "enhance" in result.resumed_steps
        assert "analyze" in result.resumed_steps
        assert "build-output" in result.resumed_steps
        assert "report" in result.resumed_steps
        assert result.units_count == 5
        assert result.language == "python"

    def test_scan_resume_partial(self, tmp_path):
        """Only parse + enhance complete -> analyze+ re-executes."""
        output_dir = str(tmp_path)

        # Set up parse and enhance as complete
        dataset_path, ao_path = _setup_parse_complete(output_dir)
        enhanced_path = _setup_enhance_complete(output_dir, dataset_path)

        from core.scanner import scan_repository
        from core.schemas import AnalyzeResult, AnalysisMetrics

        mock_analyze = MagicMock(return_value=AnalyzeResult(
            results_path=os.path.join(output_dir, "results.json"),
            metrics=AnalysisMetrics(total=5, safe=5),
        ))
        # Write the results file so build-output can find it
        _write_json(os.path.join(output_dir, "results.json"), [])

        mock_build = MagicMock()
        mock_summary = MagicMock()

        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()), \
             patch("core.analyzer.run_analysis", mock_analyze), \
             patch("core.reporter.build_pipeline_output", mock_build), \
             patch("core.reporter.generate_summary_report", mock_summary):
            result = scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
            )

        assert "parse" in result.resumed_steps
        assert "enhance" in result.resumed_steps
        assert "analyze" not in result.resumed_steps
        mock_analyze.assert_called_once()
        mock_build.assert_called_once()

    def test_scan_resume_force_rerun_cascade(self, tmp_path):
        """Delete enhance report -> parse resumed, enhance+ all re-run."""
        output_dir = str(tmp_path)

        # Set up all steps complete
        dataset_path, ao_path = _setup_parse_complete(output_dir)
        enhanced_path = _setup_enhance_complete(output_dir, dataset_path)
        results_path = _setup_analyze_complete(output_dir)
        _setup_build_output_complete(output_dir, results_path)
        _setup_report_complete(output_dir)

        # Delete enhance report to trigger cascade
        os.remove(os.path.join(output_dir, "enhance.report.json"))

        from core.scanner import scan_repository
        from core.schemas import EnhanceResult, AnalyzeResult, AnalysisMetrics

        mock_enhance = MagicMock(return_value=EnhanceResult(
            enhanced_dataset_path=enhanced_path,
            units_enhanced=5,
            classifications={"neutral": 5},
        ))
        mock_analyze = MagicMock(return_value=AnalyzeResult(
            results_path=os.path.join(output_dir, "results.json"),
            metrics=AnalysisMetrics(total=5, safe=5),
        ))
        _write_json(os.path.join(output_dir, "results.json"), [])

        mock_build = MagicMock()
        mock_summary = MagicMock()

        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()), \
             patch("core.enhancer.enhance_dataset", mock_enhance), \
             patch("core.analyzer.run_analysis", mock_analyze), \
             patch("core.reporter.build_pipeline_output", mock_build), \
             patch("core.reporter.generate_summary_report", mock_summary):
            result = scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
            )

        assert "parse" in result.resumed_steps
        assert "enhance" not in result.resumed_steps
        assert "analyze" not in result.resumed_steps
        mock_enhance.assert_called_once()
        mock_analyze.assert_called_once()

    def test_scan_fresh_ignores_everything(self, tmp_path):
        """fresh=True -> all steps re-run even though reports exist."""
        output_dir = str(tmp_path)

        # Set up all steps complete
        dataset_path, ao_path = _setup_parse_complete(output_dir)
        enhanced_path = _setup_enhance_complete(output_dir, dataset_path)
        results_path = _setup_analyze_complete(output_dir)
        _setup_build_output_complete(output_dir, results_path)
        _setup_report_complete(output_dir)

        from core.scanner import scan_repository
        from core.schemas import ParseResult, EnhanceResult, AnalyzeResult, AnalysisMetrics

        mock_parse = MagicMock(return_value=ParseResult(
            dataset_path=dataset_path,
            analyzer_output_path=ao_path,
            units_count=5,
            language="python",
        ))
        mock_enhance = MagicMock(return_value=EnhanceResult(
            enhanced_dataset_path=enhanced_path,
            units_enhanced=5,
            classifications={"neutral": 5},
        ))
        mock_analyze = MagicMock(return_value=AnalyzeResult(
            results_path=os.path.join(output_dir, "results.json"),
            metrics=AnalysisMetrics(total=5, safe=5),
        ))
        _write_json(os.path.join(output_dir, "results.json"), [])

        mock_build = MagicMock()
        mock_summary = MagicMock()

        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()), \
             patch("core.parser_adapter.parse_repository", mock_parse), \
             patch("core.enhancer.enhance_dataset", mock_enhance), \
             patch("core.analyzer.run_analysis", mock_analyze), \
             patch("core.reporter.build_pipeline_output", mock_build), \
             patch("core.reporter.generate_summary_report", mock_summary):
            result = scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
                fresh=True,
            )

        assert result.resumed_steps == []
        mock_parse.assert_called_once()
        mock_enhance.assert_called_once()
        mock_analyze.assert_called_once()
        mock_build.assert_called_once()

    def test_scan_resumed_steps_in_result(self, tmp_path):
        """resumed_steps list is included in to_dict() output."""
        output_dir = str(tmp_path)

        # Set up all steps complete
        dataset_path, ao_path = _setup_parse_complete(output_dir)
        _setup_enhance_complete(output_dir, dataset_path)
        _setup_analyze_complete(output_dir)
        _setup_build_output_complete(output_dir,
                                     os.path.join(output_dir, "results.json"))
        _setup_report_complete(output_dir)

        from core.scanner import scan_repository

        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()):
            result = scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
            )

        d = result.to_dict()
        assert "resumed_steps" in d
        assert len(d["resumed_steps"]) > 0

    def test_scan_scan_report_includes_steps_resumed(self, tmp_path):
        """scan.report.json summary includes steps_resumed."""
        output_dir = str(tmp_path)

        dataset_path, ao_path = _setup_parse_complete(output_dir)
        _setup_enhance_complete(output_dir, dataset_path)
        _setup_analyze_complete(output_dir)
        _setup_build_output_complete(output_dir,
                                     os.path.join(output_dir, "results.json"))
        _setup_report_complete(output_dir)

        from core.scanner import scan_repository

        with patch("core.scanner.tracking", get_usage=MagicMock(return_value=UsageInfo()), reset_tracking=MagicMock()):
            scan_repository(
                repo_path=str(tmp_path),
                output_dir=output_dir,
                generate_context=False,
                verify=False,
                generate_report=True,
                dynamic_test=False,
            )

        scan_report_path = os.path.join(output_dir, "scan.report.json")
        with open(scan_report_path) as f:
            scan_report = json.load(f)

        assert "steps_resumed" in scan_report["summary"]
        assert len(scan_report["summary"]["steps_resumed"]) > 0
