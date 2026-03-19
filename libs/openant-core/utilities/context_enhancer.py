"""
Context Enhancer

Uses Claude Sonnet to enhance the static analysis output from the JavaScript parser.
Identifies missing dependencies, additional callers, and extracts data flow information.

Supports two modes:
1. Single-shot (default): Fast, one prompt per unit
2. Agentic (--agentic): Iterative exploration with tool use, traces call paths

This replaces the JavaScript LLM integration in unit_generator.js and llm_context_analyzer.js.
All LLM calls are now centralized in Python.
"""

import json
import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from .llm_client import AnthropicClient, TokenTracker, get_global_tracker, reset_global_tracker
from .agentic_enhancer import RepositoryIndex, enhance_unit_with_agent, load_index_from_file


# Null logger that discards all messages (used when no logger provided)
_null_logger = logging.getLogger("null")
_null_logger.addHandler(logging.NullHandler())


# Use Sonnet for context enhancement (cost-effective auxiliary task)
CONTEXT_ENHANCEMENT_MODEL = "claude-sonnet-4-20250514"


def get_context_enhancement_prompt(
    function_id: str,
    function_name: str,
    function_code: str,
    unit_type: str,
    class_name: Optional[str],
    static_deps: list[str],
    static_callers: list[str],
    context_functions: list[dict]
) -> str:
    """
    Generate a prompt for the LLM to enhance function context.

    Args:
        function_id: Unique identifier (file:functionName)
        function_name: Function name
        function_code: The function's source code
        unit_type: Type classification (route_handler, middleware, etc.)
        class_name: Class name if method, else None
        static_deps: Dependencies identified by static analysis
        static_callers: Callers identified by static analysis
        context_functions: Other functions in the same file
    """
    deps_list = "\n".join(f"- {d}" for d in static_deps) if static_deps else "- None identified"
    callers_list = "\n".join(f"- {c}" for c in static_callers) if static_callers else "- None identified"

    context_section = ""
    if context_functions:
        context_section = "## Other Functions in Same File\n"
        for f in context_functions[:5]:  # Limit to 5 to avoid token overflow
            context_section += f"### {f.get('name', 'unknown')} ({f.get('unit_type', 'function')})\n"
            code_preview = f.get('code', '')[:200]
            if len(f.get('code', '')) > 200:
                code_preview += '...'
            context_section += f"```javascript\n{code_preview}\n```\n\n"
    else:
        context_section = "## Other Functions in Same File\nNo other functions in file.\n"

    return f"""You are analyzing a JavaScript/TypeScript function to identify all relevant context needed for security analysis.

## Target Function
**ID:** `{function_id}`
**Name:** `{function_name}`
**Type:** {unit_type}
{f'**Class:** {class_name}' if class_name else ''}

```javascript
{function_code}
```

## Static Analysis Results
**Already identified dependencies (functions called):**
{deps_list}

**Already identified callers (functions that call this):**
{callers_list}

{context_section}

## Your Task
Analyze this function and identify:

1. **Missing Dependencies**: Functions called in the code that static analysis missed
2. **Additional Callers**: Functions that likely call this function based on naming patterns
3. **Data Flow**: What data flows in and out, especially security-relevant data
4. **Imports**: External modules/files this function depends on

## Response Format
Respond with JSON only:

```json
{{
  "missing_dependencies": [
    {{"name": "functionName", "reason": "why this was missed", "likely_location": "file.ts or module"}}
  ],
  "additional_callers": [
    {{"name": "callerName", "reason": "why this likely calls the target"}}
  ],
  "data_flow": {{
    "inputs": ["req.body", "req.params.id", "etc"],
    "outputs": ["res.json(...)", "database write", "etc"],
    "tainted_variables": ["userInput", "unsanitized vars"],
    "security_relevant_flows": [
      {{"source": "req.body.query", "sink": "sql.query()", "type": "potential SQL injection"}}
    ]
  }},
  "imports": [
    {{"module": "express", "used_for": "routing"}},
    {{"module": "./utils", "used_for": "helper functions"}}
  ],
  "reasoning": "Brief explanation of your analysis",
  "confidence": 0.0-1.0
}}
```"""


class ContextEnhancer:
    """
    Enhances static analysis output with LLM-identified context.
    Uses Claude Sonnet for cost-effective context gathering.
    Tracks token usage and costs for all LLM calls.
    """

    def __init__(
        self,
        client: AnthropicClient = None,
        tracker: TokenTracker = None,
        logger: logging.Logger = None
    ):
        """
        Initialize the enhancer.

        Args:
            client: Anthropic client instance. Creates one if not provided.
            tracker: Token tracker instance. Uses global tracker if not provided.
            logger: Optional logger for structured logging. If not provided, uses print().
        """
        self.tracker = tracker or get_global_tracker()
        self.client = client or AnthropicClient(model=CONTEXT_ENHANCEMENT_MODEL, tracker=self.tracker)
        self.logger = logger or _null_logger
        self._use_logger = logger is not None
        self.stats = {
            "units_processed": 0,
            "units_enhanced": 0,
            "dependencies_added": 0,
            "callers_added": 0,
            "data_flows_extracted": 0,
            "errors": 0
        }

    def _log(self, level: str, msg: str, **extras):
        """Log a message, using logger if available, otherwise print to stderr."""
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        else:
            # Fallback to stderr for CLI usage (stdout is reserved for JSON envelope)
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"{msg} {suffix}" if suffix else msg, file=sys.stderr)

    def enhance_unit(self, unit: dict, all_units: dict) -> dict:
        """
        Enhance a single analysis unit with LLM-identified context.

        Args:
            unit: The analysis unit to enhance
            all_units: Dict of all units keyed by ID (for context lookup)

        Returns:
            Enhanced unit with data_flow field populated
        """
        self.stats["units_processed"] += 1

        function_id = unit.get("id", "unknown")
        code_section = unit.get("code", {})

        # Extract info for prompt
        function_name = code_section.get("primary_origin", {}).get("function_name", "unknown")
        function_code = code_section.get("primary_code", "")
        unit_type = unit.get("unit_type", "function")
        class_name = code_section.get("primary_origin", {}).get("class_name")

        # Get static analysis results
        static_deps = unit.get("metadata", {}).get("direct_calls", [])
        static_callers = unit.get("metadata", {}).get("direct_callers", [])

        # Gather context functions from same file
        file_path = code_section.get("primary_origin", {}).get("file_path", "")
        context_functions = []
        for other_id, other_unit in all_units.items():
            if other_id == function_id:
                continue
            other_file = other_unit.get("code", {}).get("primary_origin", {}).get("file_path", "")
            if other_file == file_path:
                context_functions.append({
                    "id": other_id,
                    "name": other_unit.get("code", {}).get("primary_origin", {}).get("function_name", "unknown"),
                    "code": other_unit.get("code", {}).get("primary_code", ""),
                    "unit_type": other_unit.get("unit_type", "function")
                })

        # Build and send prompt
        prompt = get_context_enhancement_prompt(
            function_id=function_id,
            function_name=function_name,
            function_code=function_code,
            unit_type=unit_type,
            class_name=class_name,
            static_deps=static_deps,
            static_callers=static_callers,
            context_functions=context_functions
        )

        try:
            response = self.client.analyze_sync(
                prompt,
                max_tokens=4096,
                model=CONTEXT_ENHANCEMENT_MODEL
            )
            analysis = self._parse_json_response(response)

            if analysis:
                self.stats["units_enhanced"] += 1

                # Count new items
                new_deps = len(analysis.get("missing_dependencies", []))
                new_callers = len(analysis.get("additional_callers", []))
                self.stats["dependencies_added"] += new_deps
                self.stats["callers_added"] += new_callers

                if analysis.get("data_flow", {}).get("security_relevant_flows"):
                    self.stats["data_flows_extracted"] += 1

                # Add enhancement to unit
                unit["llm_context"] = {
                    "missing_dependencies": analysis.get("missing_dependencies", []),
                    "additional_callers": analysis.get("additional_callers", []),
                    "data_flow": analysis.get("data_flow", {}),
                    "imports": analysis.get("imports", []),
                    "reasoning": analysis.get("reasoning", ""),
                    "confidence": analysis.get("confidence", 0.5)
                }
            else:
                unit["llm_context"] = self._get_default_context()

        except Exception as e:
            self.stats["errors"] += 1
            self._log("error", f"Error enhancing unit", unit_id=function_id, error=str(e))
            unit["llm_context"] = self._get_default_context()

        return unit

    def enhance_dataset(
        self,
        dataset: dict,
        batch_size: int = 10,
        progress_callback: Optional[Callable] = None,
    ) -> dict:
        """
        Enhance all units in a dataset (single-shot mode).

        Args:
            dataset: The dataset from unit_generator.js
            batch_size: Number of units to process before printing progress
            progress_callback: Optional callback(unit_id, classification, unit_elapsed)
                called after each unit completes.

        Returns:
            Enhanced dataset
        """
        units = dataset.get("units", [])
        total = len(units)

        self._log("info", f"Enhancing {total} units with LLM context (single-shot mode)", units=total)
        self._log("info", f"Model: {CONTEXT_ENHANCEMENT_MODEL}")

        # Build lookup dict for context gathering
        units_by_id = {u.get("id"): u for u in units}

        for i, unit in enumerate(units):
            if (i + 1) % batch_size == 0 or i == 0:
                self._log("info", f"Processing unit {i + 1}/{total}", unit_id=unit.get("id"))

            unit_start = time.monotonic()
            self.enhance_unit(unit, units_by_id)
            unit_elapsed = time.monotonic() - unit_start

            if progress_callback:
                ctx = unit.get("llm_context", {})
                classification = ctx.get("confidence", "unknown")
                progress_callback(unit.get("id", "?"), str(classification), unit_elapsed)

        # Get token usage stats
        token_stats = self.tracker.get_totals()

        # Update dataset metadata
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["llm_enhanced"] = True
        dataset["metadata"]["llm_model"] = CONTEXT_ENHANCEMENT_MODEL
        dataset["metadata"]["enhancement_stats"] = self.stats
        dataset["metadata"]["token_usage"] = token_stats

        self._log("info", "Enhancement complete",
                  units=self.stats['units_processed'],
                  details={
                      "units_enhanced": self.stats['units_enhanced'],
                      "dependencies_added": self.stats['dependencies_added'],
                      "callers_added": self.stats['callers_added'],
                      "data_flows_extracted": self.stats['data_flows_extracted'],
                      "errors": self.stats['errors']
                  })
        self._log("info", "Token usage",
                  input_tokens=token_stats['total_input_tokens'],
                  output_tokens=token_stats['total_output_tokens'],
                  total_tokens=token_stats['total_tokens'],
                  cost=f"${token_stats['total_cost_usd']:.4f}")

        return dataset

    def enhance_dataset_agentic(
        self,
        dataset: dict,
        analyzer_output_path: str,
        repo_path: str = None,
        batch_size: int = 5,
        verbose: bool = False,
        checkpoint_path: str = None,
        progress_callback: Optional[Callable] = None,
    ) -> dict:
        """
        Enhance all units using agentic approach with tool use.

        This mode traces call paths iteratively to understand code intent.
        More accurate but slower and more expensive than single-shot mode.

        Supports checkpoint/resume: if checkpoint_path is provided, saves progress
        after each unit and skips already-processed units on resume.

        Args:
            dataset: The dataset from unit_generator.js
            analyzer_output_path: Path to analyzer_output.json
            repo_path: Repository root path (for file reading)
            batch_size: Number of units to process before printing progress
            verbose: Print debug information
            checkpoint_path: Path to save/load checkpoint file (enables resume)
            progress_callback: Optional callback(unit_id, classification, unit_elapsed)
                called after each unit completes.

        Returns:
            Enhanced dataset with agent_context field
        """
        units = dataset.get("units", [])
        total = len(units)

        # Check for existing checkpoint
        checkpoint_data = None
        processed_ids = set()
        if checkpoint_path:
            checkpoint_file = Path(checkpoint_path)
            if checkpoint_file.exists():
                self._log("info", f"Found checkpoint at {checkpoint_path}, resuming...")
                with open(checkpoint_file, 'r') as f:
                    checkpoint_data = json.load(f)

                # Build set of already-processed unit IDs
                for cp_unit in checkpoint_data.get("units", []):
                    if cp_unit.get("agent_context") and not cp_unit["agent_context"].get("error"):
                        processed_ids.add(cp_unit.get("id"))

                # Restore units from checkpoint
                cp_units_by_id = {u.get("id"): u for u in checkpoint_data.get("units", [])}
                for unit in units:
                    unit_id = unit.get("id")
                    if unit_id in cp_units_by_id and cp_units_by_id[unit_id].get("agent_context"):
                        unit["agent_context"] = cp_units_by_id[unit_id]["agent_context"]
                        if "code" in cp_units_by_id[unit_id]:
                            unit["code"] = cp_units_by_id[unit_id]["code"]

                self._log("info", f"Restored {len(processed_ids)} already-processed units", units=len(processed_ids))

        remaining = total - len(processed_ids)
        self._log("info", f"Enhancing {remaining} units with agentic analysis ({len(processed_ids)} already done)", units=remaining)
        self._log("info", "Mode: Iterative tool use (traces call paths)")
        self._log("info", "Model: claude-sonnet-4-20250514")
        if checkpoint_path:
            self._log("info", f"Checkpoint: {checkpoint_path}")

        # Load repository index
        self._log("info", f"Loading repository index from {analyzer_output_path}")
        index = load_index_from_file(analyzer_output_path, repo_path)
        stats = index.get_statistics()
        self._log("info", f"Indexed {stats['total_functions']} functions from {stats['total_files']} files")

        # Track stats
        agentic_stats = {
            "units_processed": len(processed_ids),  # Start from checkpoint count
            "units_with_context": 0,
            "total_iterations": 0,
            "functions_added": 0,
            "security_controls_found": 0,
            "vulnerable_found": 0,
            "neutral_found": 0,
            "errors": 0
        }

        # Count stats from restored units
        for unit in units:
            agent_ctx = unit.get("agent_context", {})
            if agent_ctx and unit.get("id") in processed_ids:
                if agent_ctx.get("include_functions"):
                    agentic_stats["units_with_context"] += 1
                    agentic_stats["functions_added"] += len(agent_ctx["include_functions"])
                classification = agent_ctx.get("security_classification", "neutral")
                if classification == "security_control":
                    agentic_stats["security_controls_found"] += 1
                elif classification == "vulnerable":
                    agentic_stats["vulnerable_found"] += 1
                else:
                    agentic_stats["neutral_found"] += 1
                agentic_stats["total_iterations"] += agent_ctx.get("agent_metadata", {}).get("iterations", 0)

        processed_this_run = 0
        for i, unit in enumerate(units):
            unit_id = unit.get("id")

            # Skip already-processed units
            if unit_id in processed_ids:
                continue

            processed_this_run += 1
            if processed_this_run % batch_size == 1 or processed_this_run == 1:
                self._log("info", f"Processing unit {agentic_stats['units_processed'] + 1}/{total}", unit_id=unit_id)

            unit_start = time.monotonic()
            try:
                enhance_unit_with_agent(unit, index, self.tracker, verbose)
                agentic_stats["units_processed"] += 1

                agent_ctx = unit.get("agent_context", {})
                if agent_ctx.get("include_functions"):
                    agentic_stats["units_with_context"] += 1
                    agentic_stats["functions_added"] += len(agent_ctx["include_functions"])

                classification = agent_ctx.get("security_classification", "neutral")
                if classification == "security_control":
                    agentic_stats["security_controls_found"] += 1
                elif classification == "vulnerable":
                    agentic_stats["vulnerable_found"] += 1
                else:
                    agentic_stats["neutral_found"] += 1

                agentic_stats["total_iterations"] += agent_ctx.get("agent_metadata", {}).get("iterations", 0)

            except Exception as e:
                classification = "error"
                agentic_stats["errors"] += 1
                self._log("error", f"Error processing unit", unit_id=unit_id, error=str(e))
                unit["agent_context"] = {
                    "error": str(e),
                    "security_classification": "neutral",
                    "confidence": 0.0
                }

            unit_elapsed = time.monotonic() - unit_start
            if progress_callback:
                progress_callback(unit_id or "?", classification, unit_elapsed)

            # Save checkpoint after each unit
            if checkpoint_path:
                self._save_checkpoint(dataset, checkpoint_path, agentic_stats)

        # Get token usage stats
        token_stats = self.tracker.get_totals()

        # Update dataset metadata
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["agentic_enhanced"] = True
        dataset["metadata"]["enhancement_mode"] = "agentic"
        dataset["metadata"]["agentic_stats"] = agentic_stats
        dataset["metadata"]["token_usage"] = token_stats

        avg_iterations = agentic_stats['total_iterations'] / max(1, agentic_stats['units_processed'])
        self._log("info", "Agentic enhancement complete",
                  units=agentic_stats['units_processed'],
                  functions_added=agentic_stats['functions_added'],
                  iterations=agentic_stats['total_iterations'],
                  details={
                      "units_with_context": agentic_stats['units_with_context'],
                      "avg_iterations_per_unit": round(avg_iterations, 1),
                      "security_controls": agentic_stats['security_controls_found'],
                      "vulnerable": agentic_stats['vulnerable_found'],
                      "neutral": agentic_stats['neutral_found'],
                      "errors": agentic_stats['errors']
                  })
        self._log("info", "Token usage",
                  input_tokens=token_stats['total_input_tokens'],
                  output_tokens=token_stats['total_output_tokens'],
                  total_tokens=token_stats['total_tokens'],
                  cost=f"${token_stats['total_cost_usd']:.4f}")

        return dataset

    def _save_checkpoint(self, dataset: dict, checkpoint_path: str, agentic_stats: dict):
        """Save checkpoint to disk after each unit is processed."""
        from core.utils import atomic_write_json

        # Update metadata before saving
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["checkpoint"] = True
        dataset["metadata"]["agentic_stats"] = agentic_stats
        dataset["metadata"]["token_usage"] = self.tracker.get_totals()

        atomic_write_json(checkpoint_path, dataset)

    def get_token_stats(self) -> dict:
        """
        Get token usage statistics.

        Returns:
            Dict with total_calls, total_input_tokens, total_output_tokens, total_cost_usd
        """
        return self.tracker.get_totals()

    def get_last_call_stats(self) -> dict:
        """
        Get stats from the last LLM call.

        Returns:
            Dict with model, input_tokens, output_tokens, cost_usd
        """
        return self.client.get_last_call()

    def _get_default_context(self) -> dict:
        """Return default context when LLM call fails."""
        return {
            "missing_dependencies": [],
            "additional_callers": [],
            "data_flow": {
                "inputs": [],
                "outputs": [],
                "tainted_variables": [],
                "security_relevant_flows": []
            },
            "imports": [],
            "reasoning": "LLM analysis failed, using static analysis only",
            "confidence": 0.3
        }

    def _parse_json_response(self, response: str) -> Optional[dict]:
        """Parse JSON response from LLM, with LLM correction fallback."""
        response = response.strip()

        # Remove markdown code blocks if present
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]

        if response.endswith("```"):
            response = response[:-3]

        response = response.strip()

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(response[start:end])
                except json.JSONDecodeError:
                    pass

        # Fallback: use LLM to correct malformed JSON
        if response.strip() and hasattr(self, 'client') and self.client:
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.client)
                corrected = corrector.attempt_correction(response)
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None


def main():
    """CLI interface for context enhancement."""
    parser = argparse.ArgumentParser(
        description="Enhance parser output with LLM-identified context"
    )
    parser.add_argument(
        "input",
        help="Input dataset JSON file from unit_generator.js"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: overwrites input)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Progress reporting batch size (default: 10)"
    )
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="Use agentic mode with iterative tool use (more accurate, more expensive)"
    )
    parser.add_argument(
        "--analyzer-output",
        help="Path to analyzer_output.json (required for agentic mode)"
    )
    parser.add_argument(
        "--repo-path",
        help="Repository root path (optional, enables file reading in agentic mode)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug information (agentic mode only)"
    )
    parser.add_argument(
        "--checkpoint",
        help="Path to checkpoint file for save/resume (agentic mode only)"
    )

    args = parser.parse_args()

    # Load input
    input_path = Path(args.input)
    if not input_path.exists():
        logging.error(f"Error: Input file not found: {input_path}")
        return 1

    with open(input_path, 'r') as f:
        dataset = json.load(f)

    # Enhance
    enhancer = ContextEnhancer()

    if args.agentic:
        # Agentic mode - requires analyzer output
        if not args.analyzer_output:
            logging.error("Error: --analyzer-output is required for agentic mode")
            return 1

        analyzer_path = Path(args.analyzer_output)
        if not analyzer_path.exists():
            logging.error(f"Error: Analyzer output not found: {analyzer_path}")
            return 1

        enhanced = enhancer.enhance_dataset_agentic(
            dataset,
            analyzer_output_path=str(analyzer_path),
            repo_path=args.repo_path,
            batch_size=args.batch_size,
            verbose=args.verbose,
            checkpoint_path=args.checkpoint
        )
    else:
        # Single-shot mode (default)
        enhanced = enhancer.enhance_dataset(dataset, batch_size=args.batch_size)

    # Write output
    output_path = Path(args.output) if args.output else input_path
    with open(output_path, 'w') as f:
        json.dump(enhanced, f, indent=2)

    logging.info(f"Enhanced dataset written to: {output_path}")
    return 0


if __name__ == "__main__":
    exit(main())
