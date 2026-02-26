"""
Report Generator Module

Generates security reports and disclosure documents from OpenAnt pipeline outputs.

Usage:
    python -m report --help
    python -m report summary pipeline_output.json -o report.md
    python -m report disclosures pipeline_output.json -o disclosures/
    python -m report all pipeline_output.json -o output/
"""

from .generator import (
    generate_summary_report,
    generate_disclosure,
    generate_all,
)
from .schema import (
    PipelineOutput,
    Finding,
    ValidationError,
    validate_pipeline_output,
)

__all__ = [
    "generate_summary_report",
    "generate_disclosure",
    "generate_all",
    "PipelineOutput",
    "Finding",
    "ValidationError",
    "validate_pipeline_output",
]
