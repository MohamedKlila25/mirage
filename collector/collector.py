"""Event collector: Cowrie JSON logs -> Mirage events -> MongoDB.

Each decoy writes its own log (one folder per decoy, so the folder name is the host).
The collector tails every log, keeps only security-relevant events, converts them to
the Mirage event format, and inserts them idempotently (re-reading a file never
creates duplicates).

Run:  python -m collector.collector --logs /decoys --mongo mongodb://mongodb:27017/maya
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path

from .attack_mapping import technique_for

log = logging.getLogger("collector")

# Cowrie eventid -> Mirage event_type. Anything not listed is ignored (handshake noise).
EVENT_MAP = {
    "cowrie.session.connect": "session_start",
    "cowrie.client.version": "client_version",
    "cowrie.login.success": "login",
    "cowrie.login.failed": "login_failed",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.direct-tcpip.request": "egress",
    "cowrie.session.closed": "session_end",
}


def attacker_session_id(src_ip: str) -> str:
    """One Mirage session per attacker source, so lateral movement across decoys stays together."""
    return "att-" + "".join(c if c.isalnum() else "-" for c in (src_ip or "unknown"))


def _content(raw: dict, etype: str) -> str:
    if etype in ("login", "login_failed"):
        return f"{raw.get('username', '')}:{raw.get('password', '')}"
    if etype == "command":
        return raw.get("input", "")
    if etype == "file_download":
        if raw.get("url"):
            return raw["url"]
        return f"wrote {raw.get('destfile', '')}"
    if etype == "file_upload":
        return raw.get("filename", "")
    if etype == "egress":
        return f"{raw.get('dst_ip', '')}:{raw.get('dst_port', '')}"
    if etype == "client_version":
        return raw.get("version", "")
    if etype == "session_start":
        return f"{raw.get('src_ip', '')}:{raw.get('src_port', '')}"
    if etype == "session_end":
        return f"duration_ms={raw.get('duration_ms', '')}"
    return ""


def normalize(raw: dict, host: str, raw_ref: str | None = None) -> dict | None:
    etype = EVENT_MAP.get(raw.get("eventid", ""))
    if etype is None:
        return None
    if etype == "file_download" and not raw.get("url") and raw.get("destfile"):
        etype = "file_write"  # Cowrie logs `echo ... > file` as a download without URL
    key = "|".join(str(raw.get(k, "")) for k in ("session", "timestamp", "eventid", "input")) + "|" + host
    content = _content(raw, etype)[:4000]
    return {
        "event_id": "evt-" + hashlib.sha1(key.encode()).hexdigest()[:12],
        "ts": raw.get("timestamp", ""),
        "source": "cowrie",
        "host": host,
        "session_id": attacker_session_id(raw.get("src_ip", "")),
        "cowrie_session": raw.get("session", ""),
        "agent_id": None,                                       # set for MCP / gateway callers
        "event_type": etype,
        "src_ip": raw.get("src_ip", ""),
        "user": raw.get("username") if etype in ("login", "login_failed") else None,
        "untrusted_content": content,
        "decoy_id": None,                                       # set by Enricher when a decoy is touched
        "technique": technique_for(etype, content),
        "raw_ref": raw_ref,
        "trap": {"is_trap": True, "trap_id": f"decoy:{host}"},  # every decoy interaction is malicious
    }


TRAP_EVENT_TYPES = {"http_request", "tool_call", "trap_hit", "canary_use", "doc_retrieval", "egress",
                    "injection_attempt", "file_read"}
TRAP_SOURCES = {"wiki", "mcp", "canary", "rag", "victim"}


def normalize_trap(rec: dict, name: str, offset: int) -> dict | None:
    """A line from <trap-logs>/<service>.jsonl (written by our own services) -> event. Others are skipped."""
    if rec.get("event_type") not in TRAP_EVENT_TYPES or rec.get("source") not in TRAP_SOURCES:
        return None
    content = str(rec.get("untrusted_content", ""))[:4000]
    key = "|".join([name, str(rec.get("ts", "")), str(rec.get("src_ip", "")), content, str(rec.get("agent_id"))])
    return {
        "event_id": "evt-" + hashlib.sha1(key.encode()).hexdigest()[:12],
        "ts": rec.get("ts", ""), "source": rec["source"], "host": str(rec.get("host") or rec["source"]),
        "session_id": attacker_session_id(rec.get("src_ip", "")), "cowrie_session": "",
        "agent_id": rec.get("agent_id"), "event_type": rec["event_type"], "src_ip": rec.get("src_ip", ""),
        "user": None, "untrusted_content": content, "decoy_id": None, "technique": None,
        "raw_ref": f"trap-logs/{name}@{offset}",
        "trap": {"is_trap": True, "trap_id": str(rec.get("trap_id") or f"{rec['source']}:{rec.get('host') or ''}")},
    }


class Enricher:
    """Uses MongoDB to (1) spot canary values in events, mask them and emit a canary_use event,
    (2) link events to the decoys they touch (decoy_id, decoy.touched_by)."""

    PATH = re.compile(r"(~?/[\w.\-/]+)")
    WORD = re.compile(r"[\w.\-]+")

    def __init__(self, db):
        from canary.registry import CanaryRegistry
        self.db, self.registry, self._values = db, CanaryRegistry(db), {}

    def refresh(self):
        self._values = self.registry.values()

    def _decoy_for(self, ev: dict) -> dict | None:
        if ev["event_type"] not in ("command", "http_request", "file_read"):
            return None
        decoys = list(self.db["decoys"].find({"host": ev["host"], "session_id": {"$in": [ev["session_id"], "environment"]}},
                                             {"_id": 0, "decoy_id": 1, "path": 1}))
        if not decoys:
            return None
        text = ev["untrusted_content"]
        home = "/root" if ev.get("user") in (None, "root") else f"/home/{ev['user']}"
        paths = {p.replace("~", home, 1) if p.startswith("~") else p for p in self.PATH.findall(text)}
        for d in decoys:
            if d["path"] in paths:
                return d
        for word in self.WORD.findall(text):                     # "cat notes.txt" in the right folder
            hits = [d for d in decoys if d["path"].rsplit("/", 1)[-1] == word]
            if len(hits) == 1:
                return hits[0]
        return None

    def enrich(self, ev: dict) -> list[dict]:
        out = [ev]
        used = [(v, cid) for v, cid in self._values.items() if v and v in ev["untrusted_content"]]
        for value, cid in used:                                   # the LLM never sees a credential value
            ev["untrusted_content"] = ev["untrusted_content"].replace(value, f"[canary:{cid}]")
        if used:
            ids = [cid for _, cid in used]
            planted = self.db["decoys"].find_one({"canaries": "canary:" + ids[0]}, {"decoy_id": 1})
            out.append({**ev, "event_id": "evt-" + hashlib.sha1((ev["event_id"] + ":canary").encode()).hexdigest()[:12],
                        "event_type": "canary_use", "technique": technique_for("canary_use", ""),
                        "untrusted_content": f"canary {', '.join(ids)} used in {ev['event_type']}",
                        "decoy_id": planted["decoy_id"] if planted else None,
                        "trap": {"is_trap": True, "trap_id": "canary:" + ids[0]}})
        d = self._decoy_for(ev)
        if d:
            ev["decoy_id"] = d["decoy_id"]
            self.db["decoys"].update_one({"decoy_id": d["decoy_id"]}, {"$addToSet": {"touched_by": ev["event_id"]}})
        return out


class LogTailer:
    """Follows one file; survives truncation and rotation; never returns half-written lines."""

    def __init__(self, path: Path, state: dict):
        self.path = Path(path)
        self.state = state  # shared dict persisted by the collector: {path: {"inode", "offset"}}

    def read_new_lines(self) -> list[str]:
        return [line for _, line in self.read_new_lines_with_offsets()]

    def read_new_lines_with_offsets(self) -> list[tuple[int, str]]:
        """-> [(byte offset of the line in the file, line)]; the offset becomes the event's raw_ref."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        s = self.state.setdefault(str(self.path), {"inode": st.st_ino, "offset": 0})
        if s["inode"] != st.st_ino or st.st_size < s["offset"]:  # rotated or truncated
            s.update(inode=st.st_ino, offset=0)
        with self.path.open("rb") as f:
            f.seek(s["offset"])
            chunk = f.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return []
        start, out = s["offset"], []
        for raw in chunk[: end + 1].split(b"\n")[:-1]:
            out.append((start, raw.decode("utf-8", errors="replace").rstrip("\r")))
            start += len(raw) + 1
        s["offset"] += end + 1
        return out


class MongoSink:
    def __init__(self, db):
        self.events = db["events"]
        self.events.create_index("event_id", unique=True)
        self.events.create_index([("session_id", 1), ("ts", 1)])

    def write(self, events: list[dict]) -> int:
        new = 0
        for ev in events:
            res = self.events.update_one({"event_id": ev["event_id"]}, {"$setOnInsert": ev}, upsert=True)
            new += 1 if res.upserted_id is not None else 0
        return new


def discover_logs(root: Path) -> dict[str, Path]:
    """<root>/<host>/log/cowrie/cowrie.json  ->  {host: path}"""
    return {p.parents[2].name: p for p in sorted(Path(root).glob("*/log/cowrie/cowrie.json"))}


class Collector:
    def __init__(self, root: Path, sink, state_file: Path | None = None, enricher: Enricher | None = None,
                 trap_root: Path | None = None):
        import threading
        self.root, self.sink, self.state_file, self.enricher = Path(root), sink, state_file, enricher
        self.trap_root = Path(trap_root) if trap_root else None
        self.state = json.loads(state_file.read_text()) if state_file and state_file.exists() else {}
        self.tailers: dict[str, LogTailer] = {}
        self.trap_tailers: dict[str, LogTailer] = {}
        self.stats = {"lines": 0, "kept": 0, "new": 0, "malformed": 0}
        self._lock = threading.Lock()   # poll_once is non-reentrant: overlapping background polls would race the state file

    def _trap_events(self) -> list[dict]:
        if not self.trap_root or not self.trap_root.is_dir():
            return []
        for p in sorted(self.trap_root.glob("*.jsonl")):
            self.trap_tailers.setdefault(p.name, LogTailer(p, self.state))
        out = []
        for name, tailer in self.trap_tailers.items():
            for offset, line in tailer.read_new_lines_with_offsets():
                self.stats["lines"] += 1
                try:
                    ev = normalize_trap(json.loads(line), name, offset)
                except (json.JSONDecodeError, AttributeError):
                    self.stats["malformed"] += 1
                    continue
                if ev:
                    out.extend(self.enricher.enrich(ev) if self.enricher else [ev])
        return out

    def poll_once(self) -> int:
        if not self._lock.acquire(blocking=False):          # a poll is already running; skip this tick
            return 0
        try:
            return self._poll_once()
        finally:
            self._lock.release()

    def _poll_once(self) -> int:
        for host, path in discover_logs(self.root).items():
            self.tailers.setdefault(host, LogTailer(path, self.state))
        users = self.state.setdefault("_users", {})        # Cowrie session -> logged-in user
        if self.enricher:
            self.enricher.refresh()
        batch = self._trap_events()
        for host, tailer in self.tailers.items():
            for offset, line in tailer.read_new_lines_with_offsets():
                self.stats["lines"] += 1
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    self.stats["malformed"] += 1
                    continue
                ev = normalize(raw, host, raw_ref=f"cowrie-logs/{host}/cowrie.json@{offset}")
                if not ev:
                    continue
                if ev["event_type"] == "login":
                    users[ev["cowrie_session"]] = ev["user"]
                elif ev["user"] is None:
                    ev["user"] = users.get(ev["cowrie_session"])
                batch.extend(self.enricher.enrich(ev) if self.enricher else [ev])
        self.stats["kept"] += len(batch)
        new = self.sink.write(batch) if batch else 0
        self.stats["new"] += new
        if self.state_file:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            os.replace(tmp, self.state_file)
        return new

    def run_forever(self, interval: float = 1.0):
        while True:
            try:
                new = self.poll_once()
                if new:
                    log.info("ingested %d new events %s", new, self.stats)
            except Exception:  # keep collecting even if one poll fails
                log.exception("poll failed")
            time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default=os.environ.get("COLLECTOR_LOGS", "/decoys"))
    ap.add_argument("--mongo", default=os.environ.get("MONGO_URI", "mongodb://mongodb:27017/maya"))
    ap.add_argument("--state", default=os.environ.get("COLLECTOR_STATE", "/state/collector.json"))
    ap.add_argument("--trap-logs", default=os.environ.get("COLLECTOR_TRAP_LOGS", ""))
    ap.add_argument("--interval", type=float, default=1.0)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    from pymongo import MongoClient
    db = MongoClient(a.mongo).get_default_database()
    Path(a.state).parent.mkdir(parents=True, exist_ok=True)
    Collector(Path(a.logs), MongoSink(db), Path(a.state), Enricher(db),
              Path(a.trap_logs) if a.trap_logs else None).run_forever(a.interval)


if __name__ == "__main__":
    main()
