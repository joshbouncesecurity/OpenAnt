#!/usr/bin/env python3
"""
validate_dataset_schema.py

Validates that a dataset matches the exact schema expected by experiment.py
Run BEFORE any expensive LLM operations.
"""

import json
import sys

from utilities.file_io import read_json


def validate_unit(unit, index):
    errors = []

    # 1. Check unit.id exists
    if not unit.get("id"):
        errors.append(f"Unit {index}: missing 'id'")

    # 2. Check unit.code structure (experiment.py lines 186-196)
    code_field = unit.get("code", {})
    if not isinstance(code_field, dict):
        errors.append(f"Unit {index}: 'code' must be dict, got {type(code_field)}")
        return errors

    # 3. Check primary_code exists and is non-empty
    primary_code = code_field.get("primary_code", "")
    if not primary_code:
        errors.append(f"Unit {index}: 'code.primary_code' is empty or missing")

    # 4. Check primary_origin structure
    primary_origin = code_field.get("primary_origin", {})
    if not isinstance(primary_origin, dict):
        errors.append(f"Unit {index}: 'code.primary_origin' must be dict")
        return errors

    # 5. CRITICAL: Check enhanced flag (experiment.py line 191)
    if "enhanced" not in primary_origin:
        errors.append(f"Unit {index}: MISSING 'code.primary_origin.enhanced'")
    elif not isinstance(primary_origin.get("enhanced"), bool):
        errors.append(f"Unit {index}: 'code.primary_origin.enhanced' must be bool")

    # 6. CRITICAL: Check files_included (experiment.py line 192)
    if "files_included" not in primary_origin:
        errors.append(f"Unit {index}: MISSING 'code.primary_origin.files_included'")
    elif not isinstance(primary_origin.get("files_included"), list):
        errors.append(f"Unit {index}: 'code.primary_origin.files_included' must be list")

    # 7. If enhanced=true, files_included must have entries
    if primary_origin.get("enhanced") and not primary_origin.get("files_included"):
        errors.append(f"Unit {index}: enhanced=true but files_included is empty")

    # 8. Check file boundaries in primary_code when enhanced with multiple files
    if primary_origin.get("enhanced") and len(primary_origin.get("files_included", [])) > 1:
        if "// ========== File Boundary ==========" not in primary_code:
            errors.append(f"Unit {index}: enhanced with multiple files but no file boundaries")

    return errors


def validate_dataset(path):
    data = read_json(path)

    all_errors = []
    units = data.get("units", [])

    enhanced_count = 0
    for i, unit in enumerate(units):
        errors = validate_unit(unit, i)
        all_errors.extend(errors)

        # Count enhanced units
        code_field = unit.get("code", {})
        if isinstance(code_field, dict):
            primary_origin = code_field.get("primary_origin", {})
            if primary_origin.get("enhanced"):
                enhanced_count += 1

    return all_errors, len(units), enhanced_count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python validate_dataset_schema.py <dataset.json>")
        sys.exit(1)

    errors, total, enhanced = validate_dataset(sys.argv[1])

    print(f"Dataset: {sys.argv[1]}")
    print(f"Total units: {total}")
    print(f"Enhanced units: {enhanced}")
    print()

    if errors:
        print(f"FAILED: {len(errors)} errors:\n")
        for e in errors[:20]:  # Show first 20
            print(f"  - {e}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more errors")
        sys.exit(1)
    else:
        print("PASSED: All units match OpenAnt schema")
        sys.exit(0)
