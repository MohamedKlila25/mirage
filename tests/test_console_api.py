"""The SOC console's data API: overview, sessions, incident, approvals over MongoDB."""
import json
from pathlib import Path

import mongomock
import pytest

from collector.collector import Enricher, normalize
from control.core import ControlConfig, MirageControl
from dashboard import api
from reliability.audit import AuditLog

RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"


@pytest.fixture
def db(tmp_path):
    db = mongomock.MongoClient().maya
    # a canary used by the attacker -> canary_use event; a planted decoy
    db.canaries.insert_one({"canary_id": "password_1", "kind": "password", "value": "Summer2024!"})
    db.decoys.insert_one({"decoy_id": "dec-env", "session_id": "environment", "host": "fake-db-01",
                          "path": "/opt/app/.env", "canaries": ["canary:password_1"], "touched_by": []})
    enr = Enricher(db)
    enr.refresh()                      # load canary values, as the collector does each poll
    for e in EVENTS:
        for ev in enr.enrich(dict(e)):
            db.events.update_one({"event_id": ev["event_id"]}, {"$setOnInsert": ev}, upsert=True)
    db.sessions.insert_one({"session_id": SID, "profile": {"actor": "bot", "skill": "low", "objective": "data_theft",
                            "confidence": 0.82}, "goal": "gather_intel", "injection_detected": True,
                            "predicted_next": [{"technique": "T1021.004", "p": 0.5}]})
    db.strategies.insert_one({"session_id": SID, "status": "ok", "policy": "agent",
                              "profile": {"actor": "bot", "objective": "data_theft"}, "goal": "gather_intel",
                              "injection_detected": True, "benign_verdict_overridden": False, "at": "2026-10-10T20:05:00Z"})
    db.alerts.insert_one({"session_id": SID, "type": "injection_attempt", "owasp": "ASI01",
                          "excerpt": "SYSTEM NOTE TO AI ANALYST", "alert_key": "k1", "at": "2026-10-10T20:05:01Z"})
    db.decoys.insert_one({"decoy_id": "dec-a", "session_id": SID, "host": "fake-jump-01", "path": "/home/deploy/todo.txt",
                          "kind": "file", "policy": "agent", "canaries": ["canary:password_2"],
                          "reason": "lure to db", "touched_by": [], "created_at": "2026-10-10T20:05:02Z"})
    db.world_model.insert_one({"_id": "current", "company": "Acme", "sector": "fintech",
                               "hosts": [{"slot": "fake-jump-01", "hostname": "jump-01", "role": "jump", "closed": False},
                                         {"slot": "fake-db-01", "hostname": "db-01", "role": "db", "closed": False}]})
    return db


def test_overview(db):
    o = api.overview(db)
    assert o["environment"]["company"] == "Acme" and len(o["environment"]["hosts"]) == 2
    jump = next(h for h in o["environment"]["hosts"] if h["hostname"] == "jump-01")
    assert o["metrics"]["events"] > 0 and o["metrics"]["techniques"] >= 4
    assert o["metrics"]["canary_uses"] >= 1 and o["metrics"]["injection_alerts"] == 1
    assert o["metrics"]["decoys_planted"] == 1 and o["kill_switch"] is False


def test_sessions_carry_profile(db):
    [s] = [x for x in api.sessions(db) if x["session_id"] == SID]
    assert s["actor"] == "bot" and s["objective"] == "data_theft" and s["injection"] is True
    assert round(s["confidence"], 2) == 0.82 and s["techniques"] >= 4


def test_incident_has_timeline_brain_decoys_alerts(db):
    inc = api.incident(db, SID)
    assert inc["profile"]["actor"] == "bot" and inc["injection_detected"] is True
    assert len(inc["timeline"]) > 0
    assert any(e["event_type"] == "canary_use" and e["severity"] == "crit" for e in inc["timeline"])
    assert any(e["technique"] == "T1087.001" for e in inc["timeline"])   # cat /etc/passwd
    assert "Summer2024!" not in json.dumps(inc["timeline"])          # canary value stays masked in the UI feed
    assert inc["decoys"][0]["policy"] == "agent" and inc["decoys"][0]["canaries"] == ["canary:password_2"]
    assert inc["alerts"][0]["owasp"] == "ASI01"
    assert inc["reasoning"][0]["goal"] == "gather_intel"


def test_approvals(tmp_path, db):
    EV = EVENTS[5]["event_id"]
    (tmp_path / "t").mkdir()
    ctl = MirageControl(db, ControlConfig(deception_dir=tmp_path / "d", control_dir=tmp_path / "c",
                                        templates_dir=tmp_path / "t", exports_dir=tmp_path / "x"),
                      AuditLog(tmp_path / "a.jsonl"))
    db.events.update_one({"event_id": EV}, {"$set": {"session_id": SID}})
    ctl.call("escalate_tier", {"session_id": SID, "tier": 2}, "attacker reached tier threshold", [EV], "agent", SID)
    ap = api.approvals(db)
    assert len(ap) == 1 and ap[0]["tool"] == "escalate_tier" and ap[0]["session_id"] == SID
