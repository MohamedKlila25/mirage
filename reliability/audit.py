"""Tamper-evident audit trail.

Every gate decision and every analyst decision is one JSON line. Each line carries the
SHA-256 of the previous line, so editing or deleting any past record breaks the chain
and `verify()` points at the first broken record. Swap the file for a MongoDB
collection by keeping the same `prev_hash` / `hash` fields.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text().strip().splitlines()[-1]
        return json.loads(last)["hash"]

    def append(self, kind: str, **fields) -> dict:
        with self._lock:
            body = {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind, **fields}
            record = {**body, "prev_hash": self._last, "hash": _digest(self._last, body)}
            with self.path.open("a") as f:
                f.write(json.dumps(record, default=str) + "\n")
            self._last = record["hash"]
            return record

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def verify(self) -> tuple[bool, int | None]:
        """-> (ok, index of first bad record or None)"""
        prev = GENESIS
        for i, rec in enumerate(self.records()):
            body = {k: v for k, v in rec.items() if k not in ("prev_hash", "hash")}
            if rec.get("prev_hash") != prev or rec.get("hash") != _digest(prev, body):
                return False, i
            prev = rec["hash"]
        return True, None

    def trace(self, ref: str) -> list[dict]:
        """Every record mentioning an event id, proposal id or session id."""
        return [r for r in self.records() if ref in json.dumps(r)]
