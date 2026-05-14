"""Tests for ``utilities.atomic_io.atomic_write_json``.

These exercise the three properties that justify the helper's existence:

1. Round-trip: a written dict reads back identically.
2. Atomicity: a mid-write failure leaves the *previous* file untouched —
   no truncated/empty target on disk.
3. Same-directory temp file: required for ``os.replace`` to be atomic on
   Windows (cross-volume rename falls back to copy+delete and loses the
   atomicity guarantee).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from utilities.atomic_io import atomic_write_json


def test_roundtrip_writes_and_reads(tmp_path: Path):
    """Writing a dict and reading it back yields the same content."""
    target = tmp_path / "results.json"
    data = {
        "dataset": "geospatial_vuln12",
        "metrics": {"total": 3, "vulnerable": 1},
        "results": [{"id": "u1", "verdict": "VULNERABLE"}],
    }

    atomic_write_json(str(target), data)

    assert target.exists()
    with open(target, encoding="utf-8") as f:
        assert json.load(f) == data


def test_unicode_roundtrip_with_ensure_ascii_false(tmp_path: Path):
    """ensure_ascii=False (used by verifier) preserves non-ASCII chars."""
    target = tmp_path / "results_verified.json"
    data = {"note": "résumé — naïve café ☃"}

    atomic_write_json(str(target), data, ensure_ascii=False)

    text = target.read_text(encoding="utf-8")
    # Raw UTF-8, not \u-escaped:
    assert "résumé" in text
    assert json.loads(text) == data


def test_failure_mid_write_preserves_existing_file(tmp_path: Path, monkeypatch):
    """If json.dump raises mid-write, the previous target file is intact."""
    target = tmp_path / "results.json"
    original = {"version": 1, "stable": True}
    atomic_write_json(str(target), original)

    # Sanity check: original content is on disk before the failed write.
    assert json.loads(target.read_text(encoding="utf-8")) == original

    # Force json.dump to blow up partway through. Because atomic_write_json
    # writes to a temp file in the same directory and only os.replaces on
    # success, the existing target must be untouched.
    real_dump = json.dump

    def exploding_dump(*args, **kwargs):
        # Write a few bytes first to prove that *temp* file partial writes
        # don't reach the target — then raise.
        f = args[1]
        f.write('{"corru')
        raise RuntimeError("simulated mid-write crash")

    monkeypatch.setattr("utilities.atomic_io.json.dump", exploding_dump)

    with pytest.raises(RuntimeError, match="simulated mid-write crash"):
        atomic_write_json(str(target), {"version": 2, "broken": True})

    # Restore so subsequent assertions/teardown aren't affected.
    monkeypatch.setattr("utilities.atomic_io.json.dump", real_dump)

    # Target is unchanged: still the original content, still valid JSON.
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == original


def test_failure_cleans_up_temp_file(tmp_path: Path, monkeypatch):
    """Failed writes must not leave stray ``.tmp-`` files behind."""
    target = tmp_path / "results.json"

    def exploding_dump(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("utilities.atomic_io.json.dump", exploding_dump)

    with pytest.raises(RuntimeError):
        atomic_write_json(str(target), {"x": 1})

    leftovers = [p.name for p in tmp_path.iterdir()]
    assert leftovers == [], f"expected empty dir, found: {leftovers}"


def test_failure_with_no_existing_target_does_not_create_target(
    tmp_path: Path, monkeypatch,
):
    """If no target exists and the write fails, target must not appear."""
    target = tmp_path / "results.json"
    assert not target.exists()

    def exploding_dump(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("utilities.atomic_io.json.dump", exploding_dump)

    with pytest.raises(RuntimeError):
        atomic_write_json(str(target), {"x": 1})

    assert not target.exists()


def test_temp_file_is_in_same_directory_as_target(tmp_path: Path, monkeypatch):
    """Temp file must live in the same directory as the target.

    Cross-volume renames are not atomic on Windows; ``os.replace`` falls back
    to copy+delete, so this is load-bearing for the atomicity guarantee.
    """
    target_dir = tmp_path / "outputs"
    target_dir.mkdir()
    target = target_dir / "results.json"

    captured: dict[str, str] = {}
    real_mkstemp = __import__("tempfile").mkstemp

    def spying_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        captured["path"] = path
        captured["dir_kwarg"] = kwargs.get("dir", "")
        return fd, path

    monkeypatch.setattr("utilities.atomic_io.tempfile.mkstemp", spying_mkstemp)

    atomic_write_json(str(target), {"ok": True})

    assert "path" in captured, "tempfile.mkstemp was not called"
    tmp_dir = os.path.dirname(captured["path"])
    expected_dir = os.path.abspath(str(target_dir))
    assert os.path.abspath(tmp_dir) == expected_dir, (
        f"temp file in {tmp_dir!r}, expected {expected_dir!r}"
    )
    # And the helper passed the same dir explicitly to mkstemp.
    assert os.path.abspath(captured["dir_kwarg"]) == expected_dir


def test_overwrites_existing_file(tmp_path: Path):
    """Successful second write replaces the target's content."""
    target = tmp_path / "results.json"
    atomic_write_json(str(target), {"version": 1})
    atomic_write_json(str(target), {"version": 2, "extra": [1, 2, 3]})

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "version": 2, "extra": [1, 2, 3],
    }
