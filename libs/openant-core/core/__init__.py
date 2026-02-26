"""
OpenAnt Core — Clean product API layer.

Wraps the existing research code (experiment.py, parsers/, utilities/)
with a stable, path-based interface suitable for CLI and app consumption.

Modules:
    schemas         — JSON output envelope, result types, and StepReport
    step_report     — Context manager for timed/costed step reporting
    tracking        — Token usage and cost tracking
    parser_adapter  — Unified interface over Python/JS/Go parsers
    enhancer        — Agentic / single-shot context enhancement
    analyzer        — Stage 1 vulnerability detection
    verifier        — Stage 2 attacker simulation verification
    dynamic_tester  — Docker-isolated exploit testing
    reporter        — Report generation (pipeline output, HTML, CSV, summary, disclosure)
    scanner         — All-in-one orchestrator (parse → enhance → detect → verify → report → dynamic test)
"""
