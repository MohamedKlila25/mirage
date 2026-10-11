"""Phase 0: schemas/*.json are valid, accept the plan's examples, and match what the code writes today."""
import json
from pathlib import Path

import mongomock
import pytest
from jsonschema import Draft202012Validator

from collector.collector import normalize
from control.core import ControlConfig, MirageControl
from reliability.audit import AuditLog

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
NAMES = ["event", "decoy", "action", "summary", "groundtruth", "run"]
RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"


def errors(name: str, doc: dict) -> list[str]:
    schema = json.loads((SCHEMAS / f"{name}.json").read_text())
    as_json = json.loads(json.dumps(doc, default=str))      # Mongo datetimes -> strings, as in exports
    return [e.message for e in Draft202012Validator(schema).iter_errors(as_json)]


# Examples copied from plan section 7 (placeholders replaced by concrete values)
PLAN_EXAMPLES = {
    "event": {"event_id": "evt-000123", "ts": "2026-10-10T16:02:11Z", "source": "cowrie", "host": "fake-jump-01",
              "session_id": "att-0042", "agent_id": None, "event_type": "command", "src_ip": "10.10.0.15",
              "user": "admin", "untrusted_content": "cat /opt/app/.env", "decoy_id": "dec-0007",
              "technique": "T1552.001", "raw_ref": "cowrie-logs/fake-jump-01.json:1832"},
    "decoy": {"decoy_id": "dec-0007", "session_id": "att-0042", "host": "fake-jump-01", "kind": "file",
              "path": "/opt/app/.env", "policy": "agent", "canaries": ["canary:aws_1"],
              "reason": "Attacker listed /opt/app and read package.json: Node app, likely looking for DB creds",
              "evidence": ["evt-000118", "evt-000121"], "created_at": "2026-10-10T16:03:00Z",
              "touched_by": ["evt-000130"]},
    "action": {"action_id": "act-0031", "ts": "2026-10-10T16:03:00Z", "session_id": "att-0042", "policy": "agent",
               "tool": "plant_breadcrumb", "params": {"host": "fake-jump-01", "path": "/opt/app/.env", "template": "x"},
               "risk": "auto", "status": "executed", "blocked_by": None, "reason": "...", "evidence": ["evt-000121"],
               "decided_by": None, "decided_at": None, "reject_reason": None},
    "summary": {"session_id": "att-0042",
                "profile": {"actor": "human", "skill": "mid", "objective": "data_theft", "confidence": 0.72},
                "claims": [{"text": "The attacker read the fake .env and reused its DB password on fake-db-01",
                            "confidence": 0.9, "evidence": ["evt-000130", "evt-000141"], "check": "verified"}],
                "techniques": ["T1552.001", "T1021.004"], "next_moves": [{"technique": "T1005", "p": 0.5}],
                "injection_detected": False, "recommended": [{"tool": "recommend_block", "ioc": "10.10.0.15"}]},
    "groundtruth": {"run_id": "r-012", "persona": "data_thief", "objective": "data_theft",
                    "steps": [{"t": 3, "intent": "look for credentials", "command": "cat /opt/app/.env"}]},
    "run": {"run_id": "r-012", "policy": "agent", "attacker": "crawler", "seed": 4,
            "started": "2026-10-10T16:00:00Z", "ended": "2026-10-10T16:10:00Z", "metrics": {}},
}


@pytest.mark.parametrize("name", NAMES)
def test_schema_files_are_valid_json_schema(name):
    Draft202012Validator.check_schema(json.loads((SCHEMAS / f"{name}.json").read_text()))


@pytest.mark.parametrize("name", NAMES)
def test_plan_examples_validate(name):
    assert errors(name, PLAN_EXAMPLES[name]) == []


def test_collector_output_matches_event_schema():
    for ev in EVENTS:
        assert errors("event", ev) == [], ev


@pytest.mark.parametrize("change", [
    lambda e: e.pop("session_id"),
    lambda e: e.update(event_type="made_up"),
    lambda e: e.update(source="somewhere"),
    lambda e: e.update(technique="T99"),
])
def test_bad_events_rejected(change):
    ev = dict(EVENTS[5])
    change(ev)
    assert errors("event", ev)


@pytest.mark.parametrize("change", [
    lambda s: s["claims"][0].update(check="trust_me"),       # only the evidence checker sets this
    lambda s: s["claims"][0].update(evidence=[]),            # no citation = no claim
    lambda s: s.update(approve_all=True),
    lambda s: s["next_moves"].extend([{"technique": "T1005", "p": 0.1}] * 3),
])
def test_bad_summaries_rejected(change):
    s = json.loads(json.dumps(PLAN_EXAMPLES["summary"]))
    change(s)
    assert errors("summary", s)


def test_maya_control_records_match_action_and_decoy_schemas(tmp_path):
    db = mongomock.MongoClient().maya
    db.events.insert_many([dict(e) for e in EVENTS])
    tpl = tmp_path / "templates"
    tpl.mkdir()
    (tpl / "notes").write_text("static breadcrumb\n")
    ctl = MirageControl(db, ControlConfig(deception_dir=tmp_path / "d", control_dir=tmp_path / "c",
                                        templates_dir=tpl, exports_dir=tmp_path / "x"), AuditLog(tmp_path / "a.jsonl"))
    ev = [EVENTS[5]["event_id"]]
    ctl.call("plant_breadcrumb", {"host": "fake-jump-01", "path": "/home/admin/notes.txt", "template": "notes"},
             "first login", ev, "static", SID, "b1")                                  # executed
    ctl.call("delete_logs", {}, "x", ev, "agent", SID, "b1")                         # blocked, risk = null
    esc = ctl.call("escalate_tier", {"session_id": SID, "tier": 2}, "many commands", ev, "agent", SID, "b1")
    ctl.decide(esc["action_id"], "approve", "analyst-1")                              # approved
    blk = ctl.call("recommend_block", {"ioc": "203.0.113.50"}, "c2 server", ev, "agent", SID, "b1")
    ctl.decide(blk["action_id"], "reject", "analyst-1", "not ours to block")         # rejected
    actions = list(db.actions.find({}, {"_id": 0}))
    assert {a["status"] for a in actions} == {"executed", "blocked", "approved", "rejected"}
    for a in actions:
        assert errors("action", a) == [], a
    for d in db.decoys.find({}, {"_id": 0}):
        assert errors("decoy", d) == [], d
