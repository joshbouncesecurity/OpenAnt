"""
Report generation wrapper.

Wraps the existing report generators:
- generate_report.py   — HTML report with Chart.js
- export_csv.py        — CSV export
- report/generator.py  — LLM-based summary and disclosure documents

Also provides ``build_pipeline_output()`` which assembles analysis results
into the ``pipeline_output.json`` format consumed by ``python -m report``
and ``run_dynamic_tests()``.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import ReportResult
from utilities.file_io import read_json, write_json

# Root of openant-core
_CORE_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Pipeline output builder
# ---------------------------------------------------------------------------

def build_pipeline_output(
    results_path: str,
    output_path: str,
    repo_name: str | None = None,
    repo_url: str | None = None,
    language: str | None = None,
    commit_sha: str | None = None,
    application_type: str = "web_app",
    processing_level: str | None = None,
    step_reports: list[dict] | None = None,
) -> str:
    """Build ``pipeline_output.json`` from analysis results.

    Reads ``results.json`` or ``results_verified.json`` and transforms
    confirmed vulnerable/bypassable findings into the schema expected by
    ``report/generator.py`` and ``utilities/dynamic_tester``.

    Args:
        results_path: Path to ``results.json`` or ``results_verified.json``.
        output_path: Where to write ``pipeline_output.json``.
        repo_name: Repository name (e.g. ``"langchain-ai/langchain"``).
        repo_url: Repository URL.
        language: Primary language.
        commit_sha: Commit SHA being analyzed.
        application_type: App type for context (default ``"web_app"``).
        processing_level: Processing level used (``"reachable"``, etc.).
        step_reports: Optional list of step report dicts for duration/cost info.

    Returns:
        The *output_path* written to.
    """
    print(f"[Report] Building pipeline_output.json...", file=sys.stderr)

    experiment = read_json(results_path)

    all_results = experiment.get("results", [])
    code_by_route = experiment.get("code_by_route", {})
    metrics = experiment.get("metrics", {})

    # Use confirmed_findings if present (verified results), else filter manually
    confirmed = experiment.get("confirmed_findings")
    if confirmed is None:
        confirmed = [
            r for r in all_results
            if r.get("finding", r.get("verdict", "").lower()) in ("vulnerable", "bypassable")
            and r.get("verification", {}).get("agree", True)  # unverified = assume confirmed
        ]

    # Build findings in PipelineOutput schema
    findings_data = []
    for i, finding in enumerate(confirmed):
        route_key = finding.get("route_key") or finding.get("unit_id", "unknown")

        # Look up full result for extra fields
        full_result = next(
            (r for r in all_results
             if (r.get("route_key") or r.get("unit_id")) == route_key),
            finding,
        )

        # Extract vulnerability details from nested structure if present
        vulns = finding.get("vulnerabilities", [])
        vuln = vulns[0] if vulns else {}

        description = (
            vuln.get("description")
            or finding.get("reasoning")
            or full_result.get("reasoning")
        )

        vulnerable_code = vuln.get("vulnerable_code") or code_by_route.get(route_key)

        impact = vuln.get("impact") or finding.get("attack_vector")

        steps_to_reproduce = vuln.get("steps_to_reproduce")
        if not steps_to_reproduce:
            parts = []
            if finding.get("attack_vector"):
                parts.append(finding["attack_vector"])
            exploit_path = finding.get("exploit_path") or {}
            if exploit_path.get("data_flow"):
                parts.append("Data flow: " + " -> ".join(exploit_path["data_flow"]))
            if finding.get("verification_explanation"):
                parts.append("Verification: " + finding["verification_explanation"])
            steps_to_reproduce = "\n\n".join(parts) if parts else None

        # Determine stage2 verdict
        verification = finding.get("verification", {})
        if verification.get("agree", False):
            stage2_verdict = "confirmed" if finding.get("exploit_path") else "agreed"
        elif verification:
            stage2_verdict = "rejected"
        else:
            stage2_verdict = finding.get("finding", "vulnerable")

        findings_data.append({
            "id": f"VULN-{i+1:03d}",
            "name": vuln.get("name", finding.get("finding", "Unknown Vulnerability")),
            "short_name": vuln.get("short_name", finding.get("verdict", "vuln")),
            "location": {
                "file": route_key.split(":")[0] if ":" in route_key else "unknown",
                "function": route_key,
            },
            "cwe_id": vuln.get("cwe_id", 0),
            "cwe_name": vuln.get("cwe_name", "Unknown"),
            "stage1_verdict": finding.get("verdict", finding.get("finding", "vulnerable")),
            "stage2_verdict": stage2_verdict,
            "description": description,
            "vulnerable_code": vulnerable_code,
            "impact": impact,
            "suggested_fix": vuln.get("suggested_fix"),
            "steps_to_reproduce": steps_to_reproduce,
        })

    # Compute costs and durations from step reports
    costs = {}
    durations = {}
    skipped_steps = []
    if step_reports:
        for sr in step_reports:
            step = sr.get("step", "unknown")
            if sr.get("cost_usd"):
                costs[step] = {"actual": sr["cost_usd"]}
            if sr.get("duration_seconds"):
                durations[step] = sr["duration_seconds"]

    total_units = metrics.get("total", len(all_results))

    pipeline_output = {
        "repository": {
            "name": repo_name or experiment.get("dataset", "unknown"),
            "url": repo_url or "",
            "language": language or "",
            "commit_sha": commit_sha,
        },
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "application_type": application_type,
        "pipeline_stats": {
            "total_units": total_units,
            "reachable_units": total_units,
            "units_analyzed": total_units - metrics.get("errors", 0),
            "processing_level": processing_level,
            "costs": costs,
            "durations": durations,
            "skipped_steps": skipped_steps,
        },
        "results": {
            "vulnerable": metrics.get("vulnerable", 0) + metrics.get("bypassable", 0),
            "safe": metrics.get("safe", 0) + metrics.get("protected", 0),
            "inconclusive": metrics.get("inconclusive", 0),
            "total": total_units,
        },
        "findings": findings_data,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, pipeline_output, ensure_ascii=False)

    print(f"  pipeline_output.json: {len(findings_data)} findings", file=sys.stderr)
    print(f"  Written to {output_path}", file=sys.stderr)

    return output_path


def generate_html_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Generate an interactive HTML report with Chart.js.

    Wraps generate_report.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output HTML file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating HTML report...", file=sys.stderr)

    script = _CORE_ROOT / "generate_report.py"
    cmd = [sys.executable, str(script), results_path, dataset_path, output_path]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"HTML report generation failed (exit code {result.returncode})")

    print(f"  HTML report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="html")


def generate_csv_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Export results to CSV.

    Wraps export_csv.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output CSV file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating CSV report...", file=sys.stderr)

    script = _CORE_ROOT / "export_csv.py"
    cmd = [sys.executable, str(script), results_path, dataset_path, output_path]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"CSV export failed (exit code {result.returncode})")

    print(f"  CSV report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="csv")


def generate_summary_report(
    results_path: str,
    output_path: str,
) -> ReportResult:
    """Generate LLM-based summary report (Markdown).

    Wraps report/generator.py. Requires ANTHROPIC_API_KEY.

    Args:
        results_path: Path to results JSON (pipeline output format).
        output_path: Path for the output Markdown file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating summary report (LLM)...", file=sys.stderr)

    # Use the report module via subprocess
    cmd = [
        sys.executable, "-m", "report",
        "summary", results_path,
        "-o", output_path,
    ]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"Summary report generation failed (exit code {result.returncode})")

    print(f"  Summary report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="summary")


def generate_disclosure_docs(
    results_path: str,
    output_dir: str,
) -> ReportResult:
    """Generate per-vulnerability disclosure documents.

    Wraps report/generator.py disclosures command. Requires ANTHROPIC_API_KEY.

    Args:
        results_path: Path to results JSON (pipeline output format).
        output_dir: Directory for disclosure Markdown files.

    Returns:
        ReportResult with the output directory path.
    """
    print("[Report] Generating disclosure documents (LLM)...", file=sys.stderr)

    cmd = [
        sys.executable, "-m", "report",
        "disclosures", results_path,
        "-o", output_dir,
    ]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"Disclosure generation failed (exit code {result.returncode})")

    print(f"  Disclosures: {output_dir}", file=sys.stderr)
    return ReportResult(output_path=output_dir, format="disclosure")
