"""Shared utilities for OpenAnt core."""

import json
import os
import tempfile


def atomic_write_json(path: str, data: dict, indent: int = 2):
    """Write JSON atomically — survives crashes mid-write.

    Writes to a temporary file in the same directory, then atomically
    replaces the target. This ensures the file is either fully written
    or absent — never a corrupt partial write.
    """
    dir_name = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
        os.replace(tmp_path, path)
    except:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
