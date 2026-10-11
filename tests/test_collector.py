"""Collector tests. The fixture is a real Cowrie log recorded from a live honeypot session."""
import json
import shutil
from pathlib import Path

import mongomock
import pytest

from collector.collector import Collector, LogTailer, MongoSink, normalize
from reliability.untrusted import scan_for_injection

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie_real_session.json"
RAW = [json.loads(l) for l in FIXTURE.read_text().splitlines()]


def decoy_dir(tmp_path, host="fake-jump-01", lines=None):
    d = tmp_path / "decoys" / host / "log" / "cowrie"
    d.mkdir(parents=True)
    f = d / "cowrie.json"
    f.write_text("".join(l + "\n" for l in (lines if lines is not None else FIXTURE.read_text().splitlines())))
    return tmp_path / "decoys", f


def sink():
    return MongoSink(mongomock.MongoClient().db)


def test_normalize_real_cowrie_events():
    evs = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
    types = [e["event_type"] for e in evs]
    assert types.count("login_failed") == 1 and types.count("login") == 1
    assert types.count("command") == 6 and "file_write" in types
    assert "client_kex" not in types and len(evs) < len(RAW)          # handshake noise dropped
    cmds = [e["untrusted_content"] for e in evs if e["event_type"] == "command"]
    assert cmds[:2] == ["whoami", "uname -a"]
    login = next(e for e in evs if e["event_type"] == "login")
    assert login["untrusted_content"] == "root:Summer2024!"


def test_one_session_per_attacker_across_connections_and_hosts():
    a = [normalize(r, "fake-jump-01") for r in RAW]
    b = [normalize(r, "fake-web-01") for r in RAW]
    sessions = {e["session_id"] for e in a + b if e}
    assert sessions == {"att-127-0-0-1"}
    assert {e["host"] for e in b if e} == {"fake-web-01"}


def test_event_ids_unique_and_stable():
    ids1 = [e["event_id"] for e in (normalize(r, "h") for r in RAW) if e]
    ids2 = [e["event_id"] for e in (normalize(r, "h") for r in RAW) if e]
    assert ids1 == ids2 and len(set(ids1)) == len(ids1)


def test_end_to_end_into_mongo_is_idempotent(tmp_path):
    root, _ = decoy_dir(tmp_path)
    s = sink()
    c = Collector(root, s, tmp_path / "state.json")
    n = c.poll_once()
    expected = sum(1 for r in RAW if normalize(r, "x"))
    assert n == s.events.count_documents({}) == expected == 15
    assert Collector(root, s, None).poll_once() == 0                 # fresh reader, no duplicates
    assert s.events.count_documents({}) == 15


def test_state_file_resumes_without_rereading(tmp_path):
    root, f = decoy_dir(tmp_path)
    s = sink()
    Collector(root, s, tmp_path / "state.json").poll_once()
    c2 = Collector(root, s, tmp_path / "state.json")
    assert c2.poll_once() == 0 and c2.stats["lines"] == 0


def test_partial_line_waits_until_complete(tmp_path):
    root, f = decoy_dir(tmp_path, lines=[])
    s = sink()
    c = Collector(root, s)
    line = json.dumps(RAW[10])                                       # a command.input event
    with f.open("a") as h:
        h.write(line[:30])
    assert c.poll_once() == 0
    with f.open("a") as h:
        h.write(line[30:] + "\n")
    assert c.poll_once() == 1


def test_truncation_and_rotation_restart_from_zero(tmp_path):
    root, f = decoy_dir(tmp_path)
    s = sink()
    c = Collector(root, s)
    c.poll_once()
    f.unlink()                                                       # rotated: new file, new inode
    f.write_text(json.dumps({**RAW[10], "timestamp": "2026-10-11T00:00:00Z"}) + "\n")
    assert c.poll_once() == 1


def test_malformed_lines_skipped(tmp_path):
    root, f = decoy_dir(tmp_path, lines=["{not json", json.dumps(RAW[10])])
    c = Collector(root, sink())
    assert c.poll_once() == 1 and c.stats["malformed"] == 1


def test_new_decoy_picked_up_while_running(tmp_path):
    root, _ = decoy_dir(tmp_path)
    s = sink()
    c = Collector(root, s)
    c.poll_once()
    decoy_dir(tmp_path, host="fake-web-01")
    c.poll_once()
    assert set(s.events.distinct("host")) == {"fake-jump-01", "fake-web-01"}


def test_collected_events_feed_the_reliability_layer(tmp_path):
    root, _ = decoy_dir(tmp_path)
    s = sink()
    Collector(root, s).poll_once()
    events = list(s.events.find({"session_id": "att-127-0-0-1"}, {"_id": 0}))
    findings = scan_for_injection(events)
    assert len(findings) == 1 and "force_benign" in findings[0].patterns
