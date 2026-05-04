"""Tests for the central model configuration module."""
import re
from pathlib import Path

import pytest

from utilities import model_config
from utilities.model_config import MODEL_AUXILIARY, MODEL_DEFAULT, MODEL_PRIMARY


# Regex for a valid Claude model identifier (e.g. claude-opus-4-20250514,
# claude-sonnet-4-6, claude-haiku-4-5).
_MODEL_ID_RE = re.compile(r"^claude-(opus|sonnet|haiku)-[0-9A-Za-z-]+$")

# Regex used by the regression test to detect any hardcoded
# claude-opus-* / claude-sonnet-* string literal.
_HARDCODED_LITERAL_RE = re.compile(r"claude-(?:opus|sonnet)-[0-9][0-9A-Za-z-]*")


class TestModelConstants:
    """Constants must exist, be non-empty strings, and match Claude model id format."""

    def test_model_primary_is_valid_string(self):
        assert isinstance(MODEL_PRIMARY, str)
        assert MODEL_PRIMARY, "MODEL_PRIMARY must be non-empty"
        assert _MODEL_ID_RE.match(MODEL_PRIMARY), (
            f"MODEL_PRIMARY={MODEL_PRIMARY!r} does not match expected "
            f"claude-(opus|sonnet|haiku)-... format"
        )

    def test_model_auxiliary_is_valid_string(self):
        assert isinstance(MODEL_AUXILIARY, str)
        assert MODEL_AUXILIARY, "MODEL_AUXILIARY must be non-empty"
        assert _MODEL_ID_RE.match(MODEL_AUXILIARY), (
            f"MODEL_AUXILIARY={MODEL_AUXILIARY!r} does not match expected "
            f"claude-(opus|sonnet|haiku)-... format"
        )

    def test_model_default_is_valid_string(self):
        assert isinstance(MODEL_DEFAULT, str)
        assert MODEL_DEFAULT, "MODEL_DEFAULT must be non-empty"
        assert _MODEL_ID_RE.match(MODEL_DEFAULT)

    def test_module_exposes_all_three_constants(self):
        for name in ("MODEL_PRIMARY", "MODEL_AUXILIARY", "MODEL_DEFAULT"):
            assert hasattr(model_config, name), f"model_config missing {name}"


class TestNoHardcodedModelLiterals:
    """Regression test: no hardcoded claude-opus-*/claude-sonnet-* literals
    may reappear in libs/openant-core/*.py outside of model_config.py.

    If this test fails, replace the offending literal with an import of
    MODEL_PRIMARY / MODEL_AUXILIARY / MODEL_DEFAULT from utilities.model_config.
    """

    # Path to libs/openant-core (this file is at libs/openant-core/tests/...)
    _CORE_ROOT = Path(__file__).parent.parent

    # Files exempt from the scan (the constants live here, by design)
    _EXEMPT = {
        _CORE_ROOT / "utilities" / "model_config.py",
        # The regression test itself contains the regex pattern source.
        Path(__file__).resolve(),
    }

    def test_no_hardcoded_model_strings_outside_model_config(self):
        offenders: list[tuple[Path, int, str]] = []

        for py_path in self._CORE_ROOT.rglob("*.py"):
            resolved = py_path.resolve()
            if resolved in {p.resolve() for p in self._EXEMPT}:
                continue

            try:
                text = py_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            for lineno, line in enumerate(text.splitlines(), start=1):
                if _HARDCODED_LITERAL_RE.search(line):
                    offenders.append((py_path, lineno, line.strip()))

        if offenders:
            details = "\n".join(
                f"  {path.relative_to(self._CORE_ROOT)}:{lineno}: {snippet}"
                for path, lineno, snippet in offenders
            )
            pytest.fail(
                "Found hardcoded claude-opus-*/claude-sonnet-* literals outside "
                "utilities/model_config.py. Replace them with imports from "
                "utilities.model_config:\n" + details
            )
