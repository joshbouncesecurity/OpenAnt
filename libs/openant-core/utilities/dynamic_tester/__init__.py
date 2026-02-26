"""Dynamic testing module for OpenAnt.

Takes pipeline_output.json from the static analysis pipeline and dynamically
tests all detected vulnerabilities using Docker containers.

Public API:
    run_dynamic_tests(pipeline_output_path, output_dir) -> list[DynamicTestResult]
"""

import json
import os
import sys

from utilities.dynamic_tester.models import DynamicTestResult
from utilities.dynamic_tester.test_generator import generate_test, regenerate_test
from utilities.dynamic_tester.docker_executor import run_single_container
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester.reporter import generate_report
from utilities.llm_client import TokenTracker


def run_dynamic_tests(
    pipeline_output_path: str,
    output_dir: str | None = None,
    max_retries: int = 3,
) -> list[DynamicTestResult]:
    """Run dynamic tests for all findings in a pipeline output file.

    Args:
        pipeline_output_path: Path to pipeline_output.json
        output_dir: Directory for output files. Defaults to same directory
                    as pipeline_output_path.

    Returns:
        List of DynamicTestResult objects
    """
    # Load pipeline output
    with open(pipeline_output_path, "r") as f:
        pipeline = json.load(f)

    findings = pipeline.get("findings", [])
    repo_info = {
        "name": pipeline.get("repository", {}).get("name", "unknown"),
        "language": pipeline.get("repository", {}).get("language", "Python"),
        "application_type": pipeline.get("application_type", "unknown"),
    }

    if not findings:
        print("No findings to test.", file=sys.stderr)
        return []

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(pipeline_output_path))
    os.makedirs(output_dir, exist_ok=True)

    tracker = TokenTracker()
    results: list[DynamicTestResult] = []

    print(f"Dynamic testing {len(findings)} findings from {repo_info['name']}",
          file=sys.stderr)

    for i, finding in enumerate(findings):
        finding_id = finding.get("id", f"FINDING-{i+1}")
        print(f"\n[{i+1}/{len(findings)}] Testing {finding_id}: "
              f"{finding.get('name', 'unknown')}...", file=sys.stderr)

        # Step 1: Generate test
        cost_before = tracker.total_cost_usd
        print("  Generating test...", file=sys.stderr)
        generation = generate_test(finding, repo_info, tracker)
        generation_cost = tracker.total_cost_usd - cost_before

        if generation is None:
            print("  Test generation failed.", file=sys.stderr)
            result = collect_result(finding, None, None, generation_cost)
            results.append(result)
            continue

        print(f"  Generated (${generation_cost:.4f}). Running in Docker...",
              file=sys.stderr)

        # Step 2: Execute in Docker and retry on errors
        execution = run_single_container(generation, finding_id)
        result = collect_result(finding, generation, execution, generation_cost)
        retry_count = 0

        while result.status == "ERROR" and retry_count < max_retries:
            # Extract error message: build error > stderr > application-level details
            if execution.build_error:
                error_msg = execution.build_error
                error_type = "Build"
            elif execution.exit_code != 0 and execution.stderr:
                error_msg = execution.stderr
                error_type = "Runtime"
            else:
                error_msg = result.details
                error_type = "Application"

            if execution.timed_out:
                print(f"  Timed out — not retrying.", file=sys.stderr)
                break

            retry_count += 1
            print(f"  {error_type} error. Retry {retry_count}/{max_retries} "
                  f"with error feedback...", file=sys.stderr)

            retry_cost_before = tracker.total_cost_usd
            retry_gen = regenerate_test(
                finding, repo_info, generation,
                error_msg, tracker,
            )
            generation_cost += tracker.total_cost_usd - retry_cost_before

            if retry_gen is None:
                print(f"  Retry generation failed.", file=sys.stderr)
                break

            generation = retry_gen
            execution = run_single_container(generation, finding_id)
            result = collect_result(finding, generation, execution, generation_cost)
            print(f"  Retry {retry_count} result: {result.status} "
                  f"(${generation_cost:.4f})", file=sys.stderr)

        result.retry_count = retry_count
        results.append(result)

        print(f"  Result: {result.status} ({result.elapsed_seconds:.1f}s)",
              file=sys.stderr)

    # Generate report
    total_cost = tracker.total_cost_usd
    report_md = generate_report(results, repo_info["name"], total_cost)

    report_path = os.path.join(output_dir, "DYNAMIC_TEST_RESULTS.md")
    with open(report_path, "w") as f:
        f.write(report_md)
    print(f"\nReport written to {report_path}", file=sys.stderr)

    # Save structured results JSON
    results_path = os.path.join(output_dir, "dynamic_test_results.json")
    with open(results_path, "w") as f:
        json.dump({
            "repository": repo_info["name"],
            "total_findings": len(findings),
            "total_cost_usd": round(total_cost, 6),
            "results": [r.to_dict() for r in results],
        }, f, indent=2, ensure_ascii=False)
    print(f"Results JSON written to {results_path}", file=sys.stderr)

    return results
