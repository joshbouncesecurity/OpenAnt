"""
Report Generator - generates security reports and disclosure documents from pipeline output.
"""

import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

from .schema import validate_pipeline_output, ValidationError
from utilities.llm_client import create_anthropic_client, create_message

load_dotenv()

PROMPTS_DIR = Path(__file__).parent / "prompts"
from utilities.model_config import MODEL_PRIMARY
MODEL = MODEL_PRIMARY


def _check_api_key():
    """Check that ANTHROPIC_API_KEY or OPENANT_LOCAL_CLAUDE is configured."""
    if os.environ.get("OPENANT_LOCAL_CLAUDE", "").lower() == "true":
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        print("Set it with: export ANTHROPIC_API_KEY=sk-ant-...", file=sys.stderr)
        print("Or use: export OPENANT_LOCAL_CLAUDE=true", file=sys.stderr)
        sys.exit(1)


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    return (PROMPTS_DIR / f"{name}.txt").read_text()


def _compact_for_summary(pipeline_data: dict) -> dict:
    """Create a compact copy of pipeline_data for the summary prompt.

    Strips large fields (vulnerable_code, steps_to_reproduce, description)
    from findings to avoid exceeding the context window.
    """
    compact = {k: v for k, v in pipeline_data.items() if k != "findings"}
    compact["findings"] = []
    for f in pipeline_data.get("findings", []):
        compact["findings"].append({
            "id": f.get("id"),
            "name": f.get("name"),
            "short_name": f.get("short_name"),
            "location": f.get("location"),
            "cwe_id": f.get("cwe_id"),
            "cwe_name": f.get("cwe_name"),
            "stage1_verdict": f.get("stage1_verdict"),
            "stage2_verdict": f.get("stage2_verdict"),
            "impact": f.get("impact"),
        })
    return compact


def generate_summary_report(pipeline_data: dict) -> str:
    """Generate a summary report from pipeline data."""
    _check_api_key()
    client = create_anthropic_client()

    summary_data = _compact_for_summary(pipeline_data)
    system_prompt = load_prompt("system")
    user_prompt = load_prompt("summary").replace("{pipeline_data}", json.dumps(summary_data, indent=2))

    return create_message(
        client,
        model=MODEL,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )


def generate_disclosure(vulnerability_data: dict, product_name: str) -> str:
    """Generate a disclosure document for a single vulnerability."""
    _check_api_key()
    client = create_anthropic_client()

    system_prompt = load_prompt("system")

    vuln_with_product = {**vulnerability_data, "product_name": product_name}
    user_prompt = load_prompt("disclosure").replace(
        "{vulnerability_data}",
        json.dumps(vuln_with_product, indent=2)
    )

    return create_message(
        client,
        model=MODEL,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )


def generate_all(pipeline_path: str, output_dir: str) -> None:
    """Generate all reports from a pipeline output file."""
    pipeline_data = json.loads(Path(pipeline_path).read_text())

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate summary report
    print("Generating summary report...")
    summary = generate_summary_report(pipeline_data)
    (output_path / "SUMMARY_REPORT.md").write_text(summary)
    print(f"  -> {output_path / 'SUMMARY_REPORT.md'}")

    # Generate disclosure for each confirmed vulnerability
    disclosures_dir = output_path / "disclosures"
    disclosures_dir.mkdir(exist_ok=True)

    product_name = pipeline_data["repository"]["name"]

    for i, finding in enumerate(pipeline_data["findings"], 1):
        if finding.get("stage2_verdict") not in ("confirmed", "agreed", "vulnerable"):
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure = generate_disclosure(finding, product_name)

        safe_name = finding["short_name"].replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        (disclosures_dir / filename).write_text(disclosure)
        print(f"  -> {disclosures_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
