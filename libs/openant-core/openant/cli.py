#!/usr/bin/env python3
"""
OpenAnt CLI — Unified command-line interface for vulnerability analysis.

Commands:
    openant scan /path/to/repo --output /tmp/results
    openant parse /path/to/repo --output /tmp/results
    openant enhance dataset.json --analyzer-output ao.json --repo-path /repo -o enhanced.json
    openant analyze dataset.json --output /tmp/results
    openant verify results.json --analyzer-output ao.json --output /tmp/results
    openant build-output results.json -o pipeline_output.json
    openant dynamic-test pipeline_output.json -o /tmp/dt/
    openant report results.json --format html --output report.html

All commands output JSON to stdout and logs to stderr.
Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = error.
"""

import argparse
import json
import os
import sys
import tempfile


def _output_json(data: dict):
    """Write JSON to stdout."""
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")


def cmd_scan(args):
    """Scan a repository end-to-end."""
    from core.scanner import scan_repository
    from core.schemas import success, error

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_")

    try:
        result = scan_repository(
            repo_path=args.repo,
            output_dir=output_dir,
            language=args.language or "auto",
            processing_level=args.level,
            verify=args.verify,
            generate_context=not args.no_context,
            generate_report=not args.no_report,
            skip_tests=not args.no_skip_tests,
            limit=args.limit,
            model=args.model,
            enhance=not args.no_enhance,
            enhance_mode=args.enhance_mode,
            dynamic_test=args.dynamic_test,
        )

        _output_json(success(result.to_dict()))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_parse(args):
    """Parse a repository into a dataset."""
    from core.parser_adapter import parse_repository
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_parse_")

    try:
        with step_context("parse", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "language": args.language or "auto",
            "processing_level": args.level,
            "skip_tests": not args.no_skip_tests,
        }) as ctx:
            result = parse_repository(
                repo_path=args.repo,
                output_dir=output_dir,
                language=args.language or "auto",
                processing_level=args.level,
                skip_tests=not args.no_skip_tests,
                name=getattr(args, "name", None),
            )

            ctx.summary = {
                "total_units": result.units_count,
                "language": result.language,
                "processing_level": result.processing_level,
            }
            ctx.outputs = {
                "dataset_path": result.dataset_path,
                "analyzer_output_path": result.analyzer_output_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_enhance(args):
    """Enhance a dataset with security context."""
    from core.enhancer import enhance_dataset
    from core.schemas import success, error
    from core.step_report import step_context

    # Default output path: same dir as input, with _enhanced suffix
    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(args.dataset)
        output_path = f"{base}_enhanced{ext}"

    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("enhance", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "analyzer_output_path": os.path.abspath(args.analyzer_output) if args.analyzer_output else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
            "mode": args.mode,
        }) as ctx:
            result = enhance_dataset(
                dataset_path=args.dataset,
                output_path=output_path,
                analyzer_output_path=args.analyzer_output,
                repo_path=args.repo_path,
                mode=args.mode,
                checkpoint_path=args.checkpoint,
            )

            ctx.summary = {
                "units_enhanced": result.units_enhanced,
                "error_count": result.error_count,
                "classifications": result.classifications,
                "mode": args.mode,
            }
            ctx.outputs = {
                "enhanced_dataset_path": result.enhanced_dataset_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_analyze(args):
    """Run vulnerability analysis on a dataset.

    With --verify, chains Stage 1 detection into Stage 2 verification
    automatically (convenience shortcut for ``analyze`` + ``verify``).
    """
    from core.analyzer import run_analysis
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_analyze_")

    try:
        with step_context("analyze", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "model": args.model,
            "exploitable_only": args.exploitable_only,
            "limit": args.limit,
        }) as ctx:
            result = run_analysis(
                dataset_path=args.dataset,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
                limit=args.limit,
                model=args.model,
                exploitable_only=args.exploitable_only,
            )

            ctx.summary = {
                "total_units": result.metrics.total,
                "analyzed": result.metrics.total - result.metrics.errors,
                "verdicts": {
                    "vulnerable": result.metrics.vulnerable,
                    "bypassable": result.metrics.bypassable,
                    "inconclusive": result.metrics.inconclusive,
                    "protected": result.metrics.protected,
                    "safe": result.metrics.safe,
                    "errors": result.metrics.errors,
                },
            }
            ctx.outputs = {
                "results_path": result.results_path,
            }

        # If --verify, chain into Stage 2
        if args.verify:
            if not args.analyzer_output:
                print("[Analyze] WARNING: --verify requires --analyzer-output. "
                      "Skipping verification.", file=sys.stderr)
            else:
                from core.verifier import run_verification
                with step_context("verify", output_dir, inputs={
                    "results_path": result.results_path,
                    "analyzer_output_path": os.path.abspath(args.analyzer_output),
                }) as vctx:
                    vresult = run_verification(
                        results_path=result.results_path,
                        output_dir=output_dir,
                        analyzer_output_path=args.analyzer_output,
                        app_context_path=args.app_context,
                        repo_path=args.repo_path,
                    )

                    vctx.summary = {
                        "findings_input": vresult.findings_input,
                        "findings_verified": vresult.findings_verified,
                        "agreed": vresult.agreed,
                        "disagreed": vresult.disagreed,
                        "confirmed_vulnerabilities": vresult.confirmed_vulnerabilities,
                    }
                    vctx.outputs = {
                        "verified_results_path": vresult.verified_results_path,
                    }

                _output_json(success(vresult.to_dict()))
                if vresult.confirmed_vulnerabilities > 0:
                    return 1
                return 0

        _output_json(success(result.to_dict()))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_verify(args):
    """Run Stage 2 attacker-simulation verification on Stage 1 results."""
    from core.verifier import run_verification
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_verify_")

    try:
        with step_context("verify", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "analyzer_output_path": os.path.abspath(args.analyzer_output),
            "app_context_path": os.path.abspath(args.app_context) if args.app_context else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_verification(
                results_path=args.results,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
            )

            ctx.summary = {
                "findings_input": result.findings_input,
                "findings_verified": result.findings_verified,
                "agreed": result.agreed,
                "disagreed": result.disagreed,
                "confirmed_vulnerabilities": result.confirmed_vulnerabilities,
            }
            ctx.outputs = {
                "verified_results_path": result.verified_results_path,
            }

        _output_json(success(result.to_dict()))

        # Exit 1 if confirmed vulnerabilities
        if result.confirmed_vulnerabilities > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_build_output(args):
    """Build pipeline_output.json from analysis results."""
    from core.reporter import build_pipeline_output
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = os.path.dirname(os.path.abspath(args.output))

    try:
        with step_context("build-output", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
        }) as ctx:
            path = build_pipeline_output(
                results_path=args.results,
                output_path=args.output,
                repo_name=args.repo_name,
                repo_url=args.repo_url,
                language=args.language,
                commit_sha=args.commit_sha,
                application_type=args.app_type or "web_app",
                processing_level=args.processing_level,
            )

            ctx.outputs = {"pipeline_output_path": path}

        _output_json(success({"pipeline_output_path": path}))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_dynamic_test(args):
    """Run Docker-isolated dynamic exploit testing."""
    from core.dynamic_tester import run_tests
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="openant_dyntest_")

    try:
        with step_context("dynamic-test", output_dir, inputs={
            "pipeline_output_path": os.path.abspath(args.pipeline_output),
            "max_retries": args.max_retries,
        }) as ctx:
            result = run_tests(
                pipeline_output_path=args.pipeline_output,
                output_dir=output_dir,
                max_retries=args.max_retries,
            )

            ctx.summary = {
                "findings_tested": result.findings_tested,
                "confirmed": result.confirmed,
                "not_reproduced": result.not_reproduced,
                "blocked": result.blocked,
                "inconclusive": result.inconclusive,
                "errors": result.errors,
            }
            ctx.outputs = {
                "results_json_path": result.results_json_path,
                "results_md_path": result.results_md_path,
            }

        _output_json(success(result.to_dict()))

        if result.confirmed > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_report(args):
    """Generate reports from analysis results.

    Accepts either a ``pipeline_output.json`` (via ``--pipeline-output``) or
    a raw ``results.json`` as positional argument.  For summary/disclosure
    formats, ``pipeline_output.json`` is required; if only results are given,
    it is built automatically.
    """
    from core.reporter import (
        build_pipeline_output,
        generate_html_report,
        generate_csv_report,
        generate_summary_report,
        generate_disclosure_docs,
    )
    from core.schemas import success, error
    from core.step_report import step_context

    output_path = args.output
    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("report", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "format": args.format,
        }) as ctx:
            fmt = args.format

            # For summary/disclosure, we need pipeline_output.json
            pipeline_output_path = args.pipeline_output
            if fmt in ("summary", "disclosure") and not pipeline_output_path:
                # Auto-build pipeline_output from results
                pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")
                build_pipeline_output(
                    results_path=args.results,
                    output_path=pipeline_output_path,
                    repo_name=args.repo_name,
                )

            if fmt == "html":
                if not args.dataset:
                    _output_json(error("--dataset is required for HTML reports"))
                    return 2
                result = generate_html_report(args.results, args.dataset, output_path)
            elif fmt == "csv":
                if not args.dataset:
                    _output_json(error("--dataset is required for CSV reports"))
                    return 2
                result = generate_csv_report(args.results, args.dataset, output_path)
            elif fmt == "summary":
                result = generate_summary_report(pipeline_output_path, output_path)
            elif fmt == "disclosure":
                result = generate_disclosure_docs(pipeline_output_path, output_path)
            else:
                _output_json(error(f"Unknown format: {fmt}"))
                return 2

            ctx.summary = {"format": fmt}
            ctx.outputs = {"output_path": output_path}

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def main():
    parser = argparse.ArgumentParser(
        prog="openant",
        description="Two-stage SAST tool using Claude for vulnerability analysis",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------
    # scan — all-in-one
    # ---------------------------------------------------------------
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a repository (full pipeline: parse + enhance + detect + verify + report)",
    )
    scan_p.add_argument("repo", help="Path to repository")
    scan_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    scan_p.add_argument(
        "--language", "-l",
        choices=["auto", "python", "javascript", "go", "c", "ruby", "php"],
        default="auto",
        help="Language (default: auto-detect)",
    )
    scan_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    scan_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    scan_p.add_argument("--no-context", action="store_true", help="Skip application context generation")
    scan_p.add_argument("--no-enhance", action="store_true", help="Skip context enhancement step")
    scan_p.add_argument(
        "--enhance-mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    scan_p.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_p.add_argument("--dynamic-test", action="store_true",
                        help="Enable Docker-isolated dynamic testing (off by default)")
    scan_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    scan_p.add_argument("--limit", type=int, help="Max units to analyze")
    scan_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    scan_p.set_defaults(func=cmd_scan)

    # ---------------------------------------------------------------
    # parse — repository parsing only
    # ---------------------------------------------------------------
    parse_p = subparsers.add_parser("parse", help="Parse a repository into a dataset")
    parse_p.add_argument("repo", help="Path to repository")
    parse_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parse_p.add_argument(
        "--language", "-l",
        choices=["auto", "python", "javascript", "go", "c", "ruby", "php"],
        default="auto",
        help="Language (default: auto-detect)",
    )
    parse_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    parse_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    parse_p.add_argument("--name", help="Dataset name (default: derived from repo path)")
    parse_p.set_defaults(func=cmd_parse)

    # ---------------------------------------------------------------
    # enhance — add security context to a dataset
    # ---------------------------------------------------------------
    enhance_p = subparsers.add_parser("enhance", help="Enhance a dataset with security context")
    enhance_p.add_argument("dataset", help="Path to dataset JSON from parse step")
    enhance_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (required for agentic mode)")
    enhance_p.add_argument("--repo-path", help="Path to the repository (required for agentic mode)")
    enhance_p.add_argument("--output", "-o", help="Output path for enhanced dataset (default: {input}_enhanced.json)")
    enhance_p.add_argument("--checkpoint", help="Path to save/resume checkpoint (agentic mode)")
    enhance_p.add_argument(
        "--mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    enhance_p.set_defaults(func=cmd_enhance)

    # ---------------------------------------------------------------
    # analyze — run analysis on existing dataset
    # ---------------------------------------------------------------
    analyze_p = subparsers.add_parser("analyze", help="Run vulnerability analysis on a dataset")
    analyze_p.add_argument("dataset", help="Path to dataset JSON")
    analyze_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    analyze_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    analyze_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (for Stage 2)")
    analyze_p.add_argument("--app-context", help="Path to application_context.json")
    analyze_p.add_argument("--limit", type=int, help="Max units to analyze")
    analyze_p.add_argument("--repo-path", help="Path to the repository (for context correction)")
    analyze_p.add_argument("--exploitable-only", action="store_true",
                           help="Only analyze units classified as exploitable/vulnerable by enhancer")
    analyze_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    analyze_p.set_defaults(func=cmd_analyze)

    # ---------------------------------------------------------------
    # verify — Stage 2 attacker simulation (standalone)
    # ---------------------------------------------------------------
    verify_p = subparsers.add_parser("verify", help="Run Stage 2 verification on analysis results")
    verify_p.add_argument("results", help="Path to results.json from analyze step")
    verify_p.add_argument("--analyzer-output", required=True, help="Path to analyzer_output.json")
    verify_p.add_argument("--app-context", help="Path to application_context.json")
    verify_p.add_argument("--repo-path", help="Path to the repository")
    verify_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    verify_p.set_defaults(func=cmd_verify)

    # ---------------------------------------------------------------
    # build-output — assemble pipeline_output.json
    # ---------------------------------------------------------------
    bo_p = subparsers.add_parser("build-output", help="Build pipeline_output.json from results")
    bo_p.add_argument("results", help="Path to results.json or results_verified.json")
    bo_p.add_argument("--output", "-o", required=True, help="Output path for pipeline_output.json")
    bo_p.add_argument("--repo-name", help="Repository name (e.g. owner/repo)")
    bo_p.add_argument("--repo-url", help="Repository URL")
    bo_p.add_argument("--language", help="Primary language")
    bo_p.add_argument("--commit-sha", help="Commit SHA")
    bo_p.add_argument("--app-type", help="Application type (default: web_app)")
    bo_p.add_argument("--processing-level", help="Processing level used")
    bo_p.set_defaults(func=cmd_build_output)

    # ---------------------------------------------------------------
    # dynamic-test — Docker-isolated exploit testing
    # ---------------------------------------------------------------
    dt_p = subparsers.add_parser("dynamic-test", help="Run dynamic exploit testing (requires Docker)")
    dt_p.add_argument("pipeline_output", help="Path to pipeline_output.json")
    dt_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    dt_p.add_argument("--max-retries", type=int, default=3,
                      help="Max retries per finding on error (default: 3)")
    dt_p.set_defaults(func=cmd_dynamic_test)

    # ---------------------------------------------------------------
    # report — generate reports from results
    # ---------------------------------------------------------------
    report_p = subparsers.add_parser("report", help="Generate reports from analysis results")
    report_p.add_argument("results", help="Path to results JSON or pipeline_output.json")
    report_p.add_argument(
        "--format", "-f",
        choices=["html", "csv", "summary", "disclosure"],
        default="html",
        help="Report format (default: html)",
    )
    report_p.add_argument("--dataset", help="Path to dataset JSON (required for html/csv)")
    report_p.add_argument("--pipeline-output", help="Path to pipeline_output.json (for summary/disclosure; auto-built if absent)")
    report_p.add_argument("--repo-name", help="Repository name (used when auto-building pipeline_output)")
    report_p.add_argument("--output", "-o", required=True, help="Output path")
    report_p.set_defaults(func=cmd_report)

    args = parser.parse_args()
    return args.func(args)


def _get_version() -> str:
    """Get version from package."""
    try:
        from openant import __version__
        return __version__
    except ImportError:
        return "0.1.0"


if __name__ == "__main__":
    sys.exit(main())
