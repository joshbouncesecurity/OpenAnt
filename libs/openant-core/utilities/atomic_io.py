"""Atomic JSON file writes.

Pipeline output files (``results.json``, ``enhanced_dataset.json``,
``results_verified.json``) represent the final artefact of an expensive
multi-stage LLM pipeline. A crash, power loss, or interrupted process during
``json.dump`` can leave the target file truncated or corrupt, destroying the
output of a long-running run that may have cost real money.

``atomic_write_json`` writes the JSON to a temporary file in the **same
directory** as the target, ``fsync``s it, then ``os.replace``s it onto the
target path. ``os.replace`` is atomic on POSIX and on Windows (when both paths
sit on the same volume), so concurrent readers either see the previous file
intact or the fully-written new file — never a partial write.

The same-directory requirement matters: cross-device renames fall back to
copy+delete on most platforms (and fail outright on Windows), losing
atomicity. Callers should never pass a temp dir on a different volume.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def atomic_write_json(path: str, data: Any, *, indent: int | None = 2,
                      ensure_ascii: bool = True) -> None:
    """Atomically write ``data`` as JSON to ``path``.

    Writes to a temporary file in the same directory as ``path``, fsyncs,
    then ``os.replace``s it onto the target. If any step fails the temp
    file is removed and ``path`` is left untouched.

    Args:
        path: Destination path. Parent directory must already exist.
        data: JSON-serialisable object.
        indent: Indentation passed through to ``json.dump`` (default 2).
        ensure_ascii: Passed through to ``json.dump`` (default True).
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."

    # delete=False so we can close the handle and rename it; we clean up
    # manually on error. Same-dir is required for atomic os.replace.
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp-" + os.path.basename(path) + "-",
        suffix=".json",
        dir=directory,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync can fail on some filesystems (e.g. certain network
                # mounts). The replace below is still atomic at the VFS
                # layer; durability across power loss is best-effort.
                pass
        os.replace(tmp_path, path)
    except BaseException:
        # Clean up the temp file on any failure (including KeyboardInterrupt
        # mid-write) so we don't leave stray .tmp- files in the output dir.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
