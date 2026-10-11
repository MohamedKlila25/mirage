"""Load .env into os.environ for local runs (parse the file directly; values may contain & and ?)."""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CANDIDATES = [REPO / ".env", REPO.parent / ".env"]


def load_env(override: bool = True) -> dict:
    """Read .env into os.environ. override=True (default) refreshes already-set values, so a
    rotated AWS token in .env is picked up on the next read without restarting the process."""
    found = {}
    for path in CANDIDATES:
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                found.setdefault(k.strip(), v.strip())
    for k, v in found.items():
        if override or k not in os.environ:
            os.environ[k] = v
    return found
