"""
All-in-one scanner orchestrator.

Runs the full pipeline:

    Parse -> App Context -> Enhance -> Detect -> Verify
        -> Build pipeline_output -> Report -> Dynamic Test

This is the implementation behind ``open-ant scan <path>``.

Each step:
 1. Writes its own ``{step}.report.json`` via ``step_context``.
 2. Can be individually skipped with ``--no-{step}`` flags.
 3. Feeds its outputs into the next step.

On completion, a final ``scan.report.json`` aggregates all step reports.

Resume is always active: completed steps are skipped based on their
step reports. Use ``--fresh`` to force a full rerun.
"""

import json
import os
import shutil
import sys
from pathlib import Path

from core.schemas import (
    ScanResult, ParseResult, AnalysisMetrics, AnalyzeResult,
    VerifyResult, UsageInfo, StepReport,
)
from core.step_report import step_context
from core import tracking
from utilities.file_io import read_json


# Import app context generator (optional)
try:
    from context.application_context import (
        generate_application_context,
        save_context,
    )
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False


# ---------------------------------------------------------------------------
# Step-level resume helpers
# ---------------------------------------------------------------------------

def _check_step_completed(output_dir: str, step: str) -> dict | None:
    """Check whether a step completed successfully and its outputs are valid.

    Returns the step report dict if the step can be skipped, None otherwise.
    """
    path = os.path.join(output_dir, f"{step}.report.json")
    try:
        report = read_json(path)
    except (OSError, json.JSONDecodeError):
        return None

    if report.get("status") != "success":
        return None

    # Verify each output file exists and is valid JSON
    for key, output_path in report.get("outputs", {}).items():
        if output_path is None:
            continue
        if not os.path.exists(output_path):
            return None
        # Validate JSON for .json files
        if output_path.endswith(".json"):
            try:
                read_json(output_path)
            except (OSError, json.JSONDecodeError):
                return None

    return report


def _clean_stale_files(output_dir: str, filenames: list[str]) -> None:
    """Delete stale output files before re-executing a step."""
    for name in filenames:
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------------------
# State reconstruction helpers
# ---------------------------------------------------------------------------

def _load_parse_state(report: dict) -> ParseResult:
    """Reconstruct ParseResult from a step report."""
    summary = report.get("summary", {})
    outputs = report.get("outputs", {})
    return ParseResult(
        dataset_path=outputs.get("dataset_path", ""),
        analyzer_output_path=outputs.get("analyzer_output_path"),
        units_count=summary.get("total_units", 0),
        language=summary.get("language", "unknown"),
        processing_level=summary.get("processing_level", "all"),
    )


def _load_analyze_state(report: dict) -> AnalyzeResult:
    """Reconstruct AnalyzeResult from a step report."""
    summary = report.get("summary", {})
    outputs = report.get("outputs", {})
    verdicts = summary.get("verdicts", {})
    return AnalyzeResult(
        results_path=outputs.get("results_path", ""),
        metrics=AnalysisMetrics(
            total=summary.get("total_units", 0),
            vulnerable=verdicts.get("vulnerable", 0),
            bypassable=verdicts.get("bypassable", 0),
            inconclusive=verdicts.get("inconclusive", 0),
            protected=verdicts.get("protected", 0),
            safe=verdicts.get("safe", 0),
            errors=verdicts.get("errors", 0),
        ),
    )


def _load_verify_state(report: dict) -> VerifyResult:
    """Reconstruct VerifyResult from a step report."""
    summary = report.get("summary", {})
    outputs = report.get("outputs", {})
    return VerifyResult(
        verified_results_path=outputs.get("verified_results_path", ""),
        findings_input=summary.get("findings_input", 0),
        findings_verified=summary.get("findings_verified", 0),
        agreed=summary.get("agreed", 0),
        disagreed=summary.get("disagreed", 0),
        confirmed_vulnerabilities=summary.get("confirmed_vulnerabilities", 0),
    )


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def scan_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    processing_level: str = "reachable",
    verify: bool = False,
    generate_context: bool = True,
    generate_report: bool = True,
    skip_tests: bool = True,
    limit: int | None = None,
    model: str = "opus",
    enhance: bool = True,
    enhance_mode: str = "agentic",
    dynamic_test: bool = False,
    fresh: bool = False,
    concurrency: int = 4,
) -> ScanResult:
    """Scan a repository for vulnerabilities.

    Orchestrates the full OpenAnt pipeline:

    1. **Parse** repository into a dataset
    2. **App Context** -- generate application context (optional)
    3. **Enhance** -- add security context via agentic/single-shot LLM (optional)
    4. **Detect** -- Stage 1 vulnerability detection
    5. **Verify** -- Stage 2 attacker simulation (optional)
    6. **Build pipeline_output.json** -- bridge format for reports + dynamic tests
    7. **Report** -- summary + disclosure documents (optional)
    8. **Dynamic Test** -- Docker-isolated exploit testing (optional, off by default)

    Resume is always active: completed steps are skipped based on their
    step reports. Once any step re-executes, all subsequent steps also
    re-execute (force-rerun cascade).

    Args:
        repo_path: Path to the repository to scan.
        output_dir: Directory for all output files.
        language: ``"auto"``, ``"python"``, ``"javascript"``, ``"go"``, or ``"c"``.
        processing_level: ``"all"``, ``"reachable"``, ``"codeql"``, or ``"exploitable"``.
        verify: If True, run Stage 2 attacker simulation after detection.
        generate_context: If True, generate application context (reduces FP).
        generate_report: If True, generate summary + disclosure reports.
        skip_tests: If True, exclude test files from parsing (default: True).
        limit: Max number of units to analyze.
        model: ``"opus"`` or ``"sonnet"``.
        enhance: If True, run agentic/single-shot context enhancement.
        enhance_mode: ``"agentic"`` (thorough) or ``"single-shot"`` (fast).
        dynamic_test: If True, run Docker-isolated dynamic testing (requires Docker).
        fresh: If True, ignore all previous progress and rerun from scratch.

    Returns:
        ScanResult with paths to all generated files and metrics.
    """
    repo_path = os.path.abspath(repo_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Reset tracking
    tracking.reset_tracking()

    # If fresh, delete all checkpoint files up front
    if fresh:
        for cp_name in ["enhance_checkpoint.json", "analyze_checkpoint.json",
                        "verify_checkpoint.json"]:
            cp_path = os.path.join(output_dir, cp_name)
            if os.path.exists(cp_path):
                os.remove(cp_path)

    result = ScanResult(output_dir=output_dir)
    collected_step_reports: list[dict] = []
    force_rerun = False

    # Count total steps for progress display
    total_steps = _count_steps(
        generate_context, enhance, verify, generate_report, dynamic_test,
    )
    step_num = 0

    def _step_label(name: str) -> str:
        nonlocal step_num
        step_num += 1
        return f"[{step_num}/{total_steps}] {name}"

    _print_banner(repo_path, output_dir, language, processing_level,
                  verify, generate_context, enhance, enhance_mode,
                  generate_report, dynamic_test, fresh)

    # ---------------------------------------------------------------
    # Step 1: Parse
    # ---------------------------------------------------------------
    prev = None
    if not fresh and not force_rerun:
        prev = _check_step_completed(output_dir, "parse")

    if prev:
        print(_step_label("Parse (resumed)"), file=sys.stderr)
        parse_result = _load_parse_state(prev)
        collected_step_reports.append(prev)
        result.resumed_steps.append("parse")
    else:
        force_rerun = True
        _clean_stale_files(output_dir, [
            "dataset.json", "analyzer_output.json", "parse.report.json",
        ])

        from core.parser_adapter import parse_repository

        print(_step_label("Parsing repository..."), file=sys.stderr)

        with step_context("parse", output_dir, inputs={
            "repo_path": repo_path,
            "language": language,
            "processing_level": processing_level,
            "skip_tests": skip_tests,
        }) as ctx:
            parse_result = parse_repository(
                repo_path=repo_path,
                output_dir=output_dir,
                language=language,
                processing_level=processing_level,
                skip_tests=skip_tests,
            )

            ctx.summary = {
                "total_units": parse_result.units_count,
                "language": parse_result.language,
                "processing_level": parse_result.processing_level,
            }
            ctx.outputs = {
                "dataset_path": parse_result.dataset_path,
                "analyzer_output_path": parse_result.analyzer_output_path,
            }

        collected_step_reports.append(_load_step_report(output_dir, "parse"))

        print(f"  Parsed: {parse_result.units_count} units ({parse_result.language})",
              file=sys.stderr)

    result.dataset_path = parse_result.dataset_path
    result.analyzer_output_path = parse_result.analyzer_output_path
    result.units_count = parse_result.units_count
    result.language = parse_result.language
    print(file=sys.stderr)

    # Active dataset path -- may be updated by enhance step
    active_dataset_path = parse_result.dataset_path

    # ---------------------------------------------------------------
    # Step 2: Application Context (optional)
    # ---------------------------------------------------------------
    app_context_path = None
    if generate_context and HAS_APP_CONTEXT:
        prev = None
        if not fresh and not force_rerun:
            prev = _check_step_completed(output_dir, "app-context")

        if prev:
            print(_step_label("App context (resumed)"), file=sys.stderr)
            app_context_path = prev.get("outputs", {}).get("app_context_path")
            result.app_context_path = app_context_path
            collected_step_reports.append(prev)
            result.resumed_steps.append("app-context")
        else:
            force_rerun = True
            _clean_stale_files(output_dir, [
                "application_context.json", "app-context.report.json",
            ])

            print(_step_label("Generating application context..."), file=sys.stderr)

            with step_context("app-context", output_dir, inputs={
                "repo_path": repo_path,
            }) as ctx:
                try:
                    context = generate_application_context(Path(repo_path))
                    app_context_path = os.path.join(output_dir, "application_context.json")
                    save_context(context, Path(app_context_path))
                    result.app_context_path = app_context_path
                    ctx.summary = {"application_type": context.application_type}
                    ctx.outputs = {"app_context_path": app_context_path}
                    print(f"  App type: {context.application_type}", file=sys.stderr)
                except Exception as e:
                    print(f"  WARNING: App context generation failed: {e}", file=sys.stderr)
                    print("  Continuing without app context.", file=sys.stderr)
                    ctx.summary = {"skipped": True, "reason": str(e)}

            collected_step_reports.append(_load_step_report(output_dir, "app-context"))
    elif generate_context:
        print(_step_label("Skipping application context (module not available)."),
              file=sys.stderr)
        result.skipped_steps.append("app-context")
    else:
        print(_step_label("Skipping application context (--no-context)."),
              file=sys.stderr)
        result.skipped_steps.append("app-context")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 3: Enhance (optional)
    # ---------------------------------------------------------------
    if enhance:
        prev = None
        if not fresh and not force_rerun:
            prev = _check_step_completed(output_dir, "enhance")

        if prev:
            print(_step_label("Enhance (resumed)"), file=sys.stderr)
            enhanced_path = prev.get("outputs", {}).get("enhanced_dataset_path", "")
            result.enhanced_dataset_path = enhanced_path
            active_dataset_path = enhanced_path
            collected_step_reports.append(prev)
            result.resumed_steps.append("enhance")
        else:
            force_rerun = True
            _clean_stale_files(output_dir, [
                "dataset_enhanced.json", "enhance_checkpoint.json",
                "enhance.report.json",
            ])

            from core.enhancer import enhance_dataset

            print(_step_label("Enhancing dataset..."), file=sys.stderr)

            enhanced_path = os.path.join(output_dir, "dataset_enhanced.json")
            checkpoint_path = os.path.join(output_dir, "enhance_checkpoint.json")

            with step_context("enhance", output_dir, inputs={
                "dataset_path": active_dataset_path,
                "analyzer_output_path": parse_result.analyzer_output_path,
                "repo_path": repo_path,
                "mode": enhance_mode,
            }) as ctx:
                enhance_result = enhance_dataset(
                    dataset_path=active_dataset_path,
                    output_path=enhanced_path,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    repo_path=repo_path,
                    mode=enhance_mode,
                    checkpoint_path=checkpoint_path,
                    fresh=fresh,
                    concurrency=concurrency,
                )

                ctx.summary = {
                    "units_enhanced": enhance_result.units_enhanced,
                    "error_count": enhance_result.error_count,
                    "classifications": enhance_result.classifications,
                    "mode": enhance_mode,
                }
                ctx.outputs = {
                    "enhanced_dataset_path": enhance_result.enhanced_dataset_path,
                }

            result.enhanced_dataset_path = enhance_result.enhanced_dataset_path
            active_dataset_path = enhance_result.enhanced_dataset_path
            collected_step_reports.append(_load_step_report(output_dir, "enhance"))

            print(f"  Enhanced: {enhance_result.units_enhanced} units", file=sys.stderr)
            print(f"  Classifications: {enhance_result.classifications}", file=sys.stderr)
    else:
        print(_step_label("Skipping enhancement (--no-enhance)."), file=sys.stderr)
        result.skipped_steps.append("enhance")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 4: Detect (Stage 1)
    # ---------------------------------------------------------------
    prev = None
    if not fresh and not force_rerun:
        prev = _check_step_completed(output_dir, "analyze")

    if prev:
        print(_step_label("Analyze (resumed)"), file=sys.stderr)
        analyze_result = _load_analyze_state(prev)
        collected_step_reports.append(prev)
        result.resumed_steps.append("analyze")
    else:
        force_rerun = True
        _clean_stale_files(output_dir, [
            "results.json", "analyze_checkpoint.json", "analyze.report.json",
        ])

        from core.analyzer import run_analysis

        print(_step_label("Running vulnerability detection (Stage 1)..."), file=sys.stderr)

        with step_context("analyze", output_dir, inputs={
            "dataset_path": active_dataset_path,
            "model": model,
            "limit": limit,
        }) as ctx:
            analyze_result = run_analysis(
                dataset_path=active_dataset_path,
                output_dir=output_dir,
                analyzer_output_path=parse_result.analyzer_output_path,
                app_context_path=app_context_path,
                repo_path=repo_path,
                limit=limit,
                model=model,
                concurrency=concurrency,
            )

            ctx.summary = {
                "total_units": analyze_result.metrics.total,
                "analyzed": analyze_result.metrics.total - analyze_result.metrics.errors,
                "verdicts": {
                    "vulnerable": analyze_result.metrics.vulnerable,
                    "bypassable": analyze_result.metrics.bypassable,
                    "inconclusive": analyze_result.metrics.inconclusive,
                    "protected": analyze_result.metrics.protected,
                    "safe": analyze_result.metrics.safe,
                    "errors": analyze_result.metrics.errors,
                },
            }
            ctx.outputs = {"results_path": analyze_result.results_path}

        collected_step_reports.append(_load_step_report(output_dir, "analyze"))

    result.results_path = analyze_result.results_path
    result.metrics = analyze_result.metrics
    print(file=sys.stderr)

    # Active results path -- may be updated by verify step
    active_results_path = analyze_result.results_path

    # ---------------------------------------------------------------
    # Step 5: Verify (Stage 2) -- optional
    # ---------------------------------------------------------------
    has_findings = (
        analyze_result.metrics.vulnerable > 0
        or analyze_result.metrics.bypassable > 0
    )

    if verify and has_findings:
        prev = None
        if not fresh and not force_rerun:
            prev = _check_step_completed(output_dir, "verify")

        if prev:
            print(_step_label("Verify (resumed)"), file=sys.stderr)
            verify_result = _load_verify_state(prev)
            result.verified_results_path = verify_result.verified_results_path
            active_results_path = verify_result.verified_results_path
            collected_step_reports.append(prev)
            result.resumed_steps.append("verify")

            # Update metrics from resumed verification
            result.metrics = AnalysisMetrics(
                total=analyze_result.metrics.total,
                vulnerable=verify_result.confirmed_vulnerabilities,
                bypassable=0,
                inconclusive=analyze_result.metrics.inconclusive,
                protected=analyze_result.metrics.protected,
                safe=analyze_result.metrics.safe + verify_result.disagreed,
                errors=analyze_result.metrics.errors,
                verified=verify_result.findings_verified,
                stage2_agreed=verify_result.agreed,
                stage2_disagreed=verify_result.disagreed,
            )
        else:
            force_rerun = True
            _clean_stale_files(output_dir, [
                "results_verified.json", "verify_checkpoint.json",
                "verify.report.json",
            ])

            from core.verifier import run_verification

            print(_step_label("Running verification (Stage 2)..."), file=sys.stderr)

            with step_context("verify", output_dir, inputs={
                "results_path": analyze_result.results_path,
                "analyzer_output_path": parse_result.analyzer_output_path,
            }) as ctx:
                verify_result = run_verification(
                    results_path=analyze_result.results_path,
                    output_dir=output_dir,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    app_context_path=app_context_path,
                    repo_path=repo_path,
                    concurrency=concurrency,
                )

                ctx.summary = {
                    "findings_input": verify_result.findings_input,
                    "findings_verified": verify_result.findings_verified,
                    "agreed": verify_result.agreed,
                    "disagreed": verify_result.disagreed,
                    "confirmed_vulnerabilities": verify_result.confirmed_vulnerabilities,
                }
                ctx.outputs = {
                    "verified_results_path": verify_result.verified_results_path,
                }

            result.verified_results_path = verify_result.verified_results_path
            active_results_path = verify_result.verified_results_path
            collected_step_reports.append(_load_step_report(output_dir, "verify"))

            print(f"  Confirmed: {verify_result.confirmed_vulnerabilities} vulnerabilities",
                  file=sys.stderr)

            # Update metrics from verified results
            result.metrics = AnalysisMetrics(
                total=analyze_result.metrics.total,
                vulnerable=verify_result.confirmed_vulnerabilities,
                bypassable=0,
                inconclusive=analyze_result.metrics.inconclusive,
                protected=analyze_result.metrics.protected,
                safe=analyze_result.metrics.safe + verify_result.disagreed,
                errors=analyze_result.metrics.errors,
                verified=verify_result.findings_verified,
                stage2_agreed=verify_result.agreed,
                stage2_disagreed=verify_result.disagreed,
            )
    elif verify and not has_findings:
        print(_step_label("Skipping verification (no vulnerable findings)."),
              file=sys.stderr)
        result.skipped_steps.append("verify")
    else:
        print(_step_label("Skipping verification (--no-verify or not requested)."),
              file=sys.stderr)
        result.skipped_steps.append("verify")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 6: Build pipeline_output.json
    # ---------------------------------------------------------------
    prev = None
    if not fresh and not force_rerun:
        prev = _check_step_completed(output_dir, "build-output")

    if prev:
        print(_step_label("Build output (resumed)"), file=sys.stderr)
        pipeline_output_path = prev.get("outputs", {}).get("pipeline_output_path", "")
        collected_step_reports.append(prev)
        result.resumed_steps.append("build-output")
    else:
        force_rerun = True
        _clean_stale_files(output_dir, [
            "pipeline_output.json", "build-output.report.json",
        ])

        from core.reporter import build_pipeline_output

        print(_step_label("Building pipeline_output.json..."), file=sys.stderr)

        pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")

        with step_context("build-output", output_dir, inputs={
            "results_path": active_results_path,
        }) as ctx:
            build_pipeline_output(
                results_path=active_results_path,
                output_path=pipeline_output_path,
                repo_name=os.path.basename(repo_path),
                language=result.language,
                application_type=(
                    app_context_path and _read_app_type(app_context_path)
                ) or "web_app",
                processing_level=processing_level,
                step_reports=collected_step_reports,
            )

            ctx.outputs = {"pipeline_output_path": pipeline_output_path}

        collected_step_reports.append(_load_step_report(output_dir, "build-output"))
    result.pipeline_output_path = pipeline_output_path
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 7: Report (optional)
    # ---------------------------------------------------------------
    if generate_report:
        prev = None
        if not fresh and not force_rerun:
            prev = _check_step_completed(output_dir, "report")

        if prev:
            print(_step_label("Report (resumed)"), file=sys.stderr)
            result.summary_path = prev.get("outputs", {}).get("summary_path")
            collected_step_reports.append(prev)
            result.resumed_steps.append("report")
        else:
            force_rerun = True
            _clean_stale_files(output_dir, ["report.report.json"])

            from core.reporter import generate_summary_report, generate_disclosure_docs

            print(_step_label("Generating reports..."), file=sys.stderr)

            with step_context("report", output_dir, inputs={
                "pipeline_output_path": pipeline_output_path,
            }) as ctx:
                report_dir = os.path.join(output_dir, "report")
                os.makedirs(report_dir, exist_ok=True)

                summary_path = os.path.join(report_dir, "SUMMARY_REPORT.md")
                disclosures_dir = os.path.join(report_dir, "disclosures")

                outputs = {}

                try:
                    generate_summary_report(pipeline_output_path, summary_path)
                    result.summary_path = summary_path
                    outputs["summary_path"] = summary_path
                    print(f"  Summary: {summary_path}", file=sys.stderr)
                except Exception as e:
                    print(f"  WARNING: Summary report failed: {e}", file=sys.stderr)
                    ctx.errors.append(f"Summary report: {e}")

                # Only generate disclosures if there are findings
                if has_findings:
                    try:
                        generate_disclosure_docs(pipeline_output_path, disclosures_dir)
                        outputs["disclosures_dir"] = disclosures_dir
                        print(f"  Disclosures: {disclosures_dir}", file=sys.stderr)
                    except Exception as e:
                        print(f"  WARNING: Disclosure docs failed: {e}", file=sys.stderr)
                        ctx.errors.append(f"Disclosure docs: {e}")

                ctx.summary = {"formats_generated": list(outputs.keys())}
                ctx.outputs = outputs

            collected_step_reports.append(_load_step_report(output_dir, "report"))
    else:
        print(_step_label("Skipping report generation (--no-report)."), file=sys.stderr)
        result.skipped_steps.append("report")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 8: Dynamic Test (optional, off by default)
    # ---------------------------------------------------------------
    if dynamic_test and has_findings:
        if not shutil.which("docker"):
            print(_step_label("Skipping dynamic test (Docker not found)."),
                  file=sys.stderr)
            result.skipped_steps.append("dynamic-test")
        else:
            prev = None
            if not fresh and not force_rerun:
                prev = _check_step_completed(output_dir, "dynamic-test")

            if prev:
                print(_step_label("Dynamic test (resumed)"), file=sys.stderr)
                result.dynamic_test_path = prev.get("outputs", {}).get("results_json_path")
                collected_step_reports.append(prev)
                result.resumed_steps.append("dynamic-test")
            else:
                force_rerun = True
                _clean_stale_files(output_dir, ["dynamic-test.report.json"])

                from core.dynamic_tester import run_tests

                print(_step_label("Running dynamic tests (Docker)..."), file=sys.stderr)

                with step_context("dynamic-test", output_dir, inputs={
                    "pipeline_output_path": pipeline_output_path,
                }) as ctx:
                    dt_result = run_tests(
                        pipeline_output_path=pipeline_output_path,
                        output_dir=output_dir,
                    )

                    ctx.summary = {
                        "findings_tested": dt_result.findings_tested,
                        "confirmed": dt_result.confirmed,
                        "not_reproduced": dt_result.not_reproduced,
                        "blocked": dt_result.blocked,
                        "inconclusive": dt_result.inconclusive,
                        "errors": dt_result.errors,
                    }
                    ctx.outputs = {
                        "results_json_path": dt_result.results_json_path,
                        "results_md_path": dt_result.results_md_path,
                    }

                result.dynamic_test_path = dt_result.results_json_path
                collected_step_reports.append(
                    _load_step_report(output_dir, "dynamic-test"),
                )

                print(f"  Dynamic test: {dt_result.confirmed} confirmed, "
                      f"{dt_result.not_reproduced} not reproduced", file=sys.stderr)
    elif dynamic_test and not has_findings:
        print(_step_label("Skipping dynamic test (no findings to test)."),
              file=sys.stderr)
        result.skipped_steps.append("dynamic-test")
    else:
        print(_step_label("Skipping dynamic test (not enabled)."), file=sys.stderr)
        result.skipped_steps.append("dynamic-test")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Final: Aggregate scan report
    # ---------------------------------------------------------------
    result.usage = tracking.get_usage()
    result.step_reports = collected_step_reports

    _write_scan_report(output_dir, result, collected_step_reports)
    _print_summary(result)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _count_steps(
    generate_context: bool,
    enhance: bool,
    verify: bool,
    generate_report: bool,
    dynamic_test: bool,
) -> int:
    """Count total steps for progress display (always includes parse, detect, build-output)."""
    count = 3  # parse + detect + build-output (always run)
    if generate_context:
        count += 1
    if enhance:
        count += 1
    if verify:
        count += 1
    if generate_report:
        count += 1
    if dynamic_test:
        count += 1
    return count


def _load_step_report(output_dir: str, step: str) -> dict:
    """Load a step report JSON from disk. Returns empty dict on failure."""
    path = os.path.join(output_dir, f"{step}.report.json")
    try:
        return read_json(path)
    except Exception:
        return {"step": step, "status": "unknown"}


def _read_app_type(app_context_path: str) -> str | None:
    """Read application_type from an app context JSON file."""
    try:
        data = read_json(app_context_path)
        return data.get("application_type")
    except Exception:
        return None


def _write_scan_report(
    output_dir: str,
    result: ScanResult,
    step_reports: list[dict],
) -> str:
    """Write ``scan.report.json`` -- the aggregate report for the full pipeline."""
    total_cost = sum(sr.get("cost_usd", 0) for sr in step_reports)
    total_duration = sum(sr.get("duration_seconds", 0) for sr in step_reports)
    total_input = sum(
        sr.get("token_usage", {}).get("input_tokens", 0) for sr in step_reports
    )
    total_output = sum(
        sr.get("token_usage", {}).get("output_tokens", 0) for sr in step_reports
    )

    scan_report = StepReport(
        step="scan",
        summary={
            "units_count": result.units_count,
            "language": result.language,
            "metrics": result.metrics.to_dict(),
            "steps_completed": [sr.get("step") for sr in step_reports],
            "steps_skipped": result.skipped_steps,
            "steps_resumed": result.resumed_steps,
        },
        inputs={"repo_path": result.output_dir.replace(os.path.abspath("."), ".")},
        outputs={
            "dataset_path": result.dataset_path,
            "enhanced_dataset_path": result.enhanced_dataset_path,
            "results_path": result.results_path,
            "verified_results_path": result.verified_results_path,
            "pipeline_output_path": result.pipeline_output_path,
            "summary_path": result.summary_path,
            "dynamic_test_path": result.dynamic_test_path,
        },
        cost_usd=round(total_cost, 6),
        duration_seconds=round(total_duration, 2),
        token_usage={
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
        },
    )

    path = scan_report.write(output_dir)
    print(f"[Scan] Aggregate report: {path}", file=sys.stderr)
    return path


def _print_banner(
    repo_path: str,
    output_dir: str,
    language: str,
    processing_level: str,
    verify: bool,
    generate_context: bool,
    enhance: bool,
    enhance_mode: str,
    generate_report: bool,
    dynamic_test: bool,
    fresh: bool = False,
) -> None:
    """Print the scan configuration banner."""
    print("=" * 60, file=sys.stderr)
    print("OPENANT SCAN", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Repository:    {repo_path}", file=sys.stderr)
    print(f"  Output:        {output_dir}", file=sys.stderr)
    print(f"  Language:      {language}", file=sys.stderr)
    print(f"  Level:         {processing_level}", file=sys.stderr)
    print(f"  Enhance:       {enhance} ({enhance_mode})", file=sys.stderr)
    print(f"  Verify (S2):   {verify}", file=sys.stderr)
    print(f"  App context:   {generate_context}", file=sys.stderr)
    print(f"  Report:        {generate_report}", file=sys.stderr)
    print(f"  Dynamic test:  {dynamic_test}", file=sys.stderr)
    if fresh:
        print(f"  Fresh:         True", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


def _print_summary(result: ScanResult) -> None:
    """Print the final scan summary."""
    print("=" * 60, file=sys.stderr)
    print("SCAN COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Units analyzed: {result.metrics.total}", file=sys.stderr)
    print(f"  Vulnerable:     {result.metrics.vulnerable}", file=sys.stderr)
    print(f"  Bypassable:     {result.metrics.bypassable}", file=sys.stderr)
    print(f"  Protected:      {result.metrics.protected}", file=sys.stderr)
    print(f"  Safe:           {result.metrics.safe}", file=sys.stderr)
    print(f"  Inconclusive:   {result.metrics.inconclusive}", file=sys.stderr)
    print(f"  Errors:         {result.metrics.errors}", file=sys.stderr)
    if result.metrics.verified:
        print(f"  Verified:       {result.metrics.verified} "
              f"({result.metrics.stage2_agreed} agreed, "
              f"{result.metrics.stage2_disagreed} disagreed)", file=sys.stderr)
    print(f"  Cost:           ${result.usage.total_cost_usd:.4f}", file=sys.stderr)
    print(f"  Output:         {result.output_dir}", file=sys.stderr)
    if result.resumed_steps:
        print(f"  Resumed:        {', '.join(result.resumed_steps)}", file=sys.stderr)
    if result.skipped_steps:
        print(f"  Skipped:        {', '.join(result.skipped_steps)}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
