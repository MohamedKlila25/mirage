"""SIEM export (ECS + Splunk/Elastic) and the incident / NIS2 report drafts."""
import json
from pathlib import Path

import mongomock
import pytest

from integrations.reports import incident_report_md, nis2_draft_md
from integrations.siem import export_all, export_alerts, siem_queries, to_ecs

SID = "att-10-100-0-50"


@pytest.fixture
def db():
    db = mongomock.MongoClient().maya
    db.events.insert_many([
        {"event_id": "e1", "session_id": SID, "ts": "2026-10-10T20:00:01Z", "source": "cowrie", "host": "pay-jump-01",
         "event_type": "command", "src_ip": "10.100.0.9", "user": "deploy", "untrusted_content": "cat /opt/x/.env",
         "technique": "T1552.001", "trap": {"is_trap": True, "trap_id": "decoy:pay-jump-01"}},
        {"event_id": "e2", "session_id": SID, "ts": "2026-10-10T20:00:03Z", "source": "mcp", "host": "mcp-company",
         "event_type": "trap_hit", "agent_id": "victim-assistant", "untrusted_content": "called export_all_customers",
         "trap": {"is_trap": True, "trap_id": "mcp:export_all_customers"}},
        {"event_id": "e3", "session_id": SID, "ts": "2026-10-10T20:00:05Z", "source": "mcp", "host": "mcp-company",
         "event_type": "egress", "untrusted_content": "email to audit@external-check.io",
         "trap": {"is_trap": True, "trap_id": "exfil"}},
    ])
    db.sessions.insert_one({"session_id": SID, "profile": {"actor": "ai_agent", "skill": "high",
                            "objective": "exfiltrate customer data", "confidence": 0.9}, "goal": "contain",
                            "injection_detected": False,
                            "summary": {"claims": [{"text": "read `cat /opt/x/.env`", "confidence": 0.9,
                                        "evidence": ["e1"], "check": "verified"}],
                                        "total": 1, "verified": 1, "weak": 0, "unsupported": 0,
                                        "hallucination_rate": 0.0, "grounding_rate": 1.0}})
    db.actions.insert_many([
        {"session_id": SID, "tool": "revoke_agent_token", "status": "pending", "params": {"agent_id": "victim-assistant"},
         "reason": "hijacked agent", "ts": "t"},
        {"session_id": SID, "tool": "recommend_block", "status": "approved", "params": {"ioc": "external-check.io"}, "ts": "t"},
    ])
    db.decoys.insert_one({"session_id": SID, "host": "pay-jump-01", "path": "/opt/x/.env", "kind": "file",
                          "policy": "agent", "reason": "lure", "touched_by": ["e1"], "created_at": "t"})
    return db


def test_to_ecs_maps_fields():
    e = to_ecs({"ts": "2026-10-10T20:00:01Z", "event_type": "canary_use", "src_ip": "1.2.3.4", "host": "h",
                "technique": "T1078", "session_id": SID, "trap": {"is_trap": True, "trap_id": "c1"}})
    assert e["@timestamp"] and e["event.kind"] == "alert" and e["event.action"] == "canary_use"
    assert e["threat.technique.id"] == "T1078" and e["labels.owasp"] == "ASI03" and e["source.ip"] == "1.2.3.4"


def test_export_alerts_writes_ecs_jsonl(db, tmp_path):
    n = export_alerts(db, tmp_path / "alerts.jsonl")
    lines = [json.loads(l) for l in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert n == 3 and all("@timestamp" in l and "event.action" in l for l in lines)
    assert any(l.get("labels.owasp") == "ASI02" for l in lines)      # the trap_hit


def test_siem_queries_cover_techniques_and_iocs(db):
    md = siem_queries(db)
    assert "T1552.001" in md and "```spl" in md and "ES|QL" in md
    assert "external-check.io" in md                                 # approved IOC


def test_export_all(db, tmp_path):
    out = export_all(db, tmp_path)
    assert out["alerts"] == 3 and Path(out["queries_file"]).exists()


def test_incident_report_has_profile_summary_and_recommendations(db):
    md = incident_report_md(db, SID)
    assert "Incident report" in md and "exfiltrate customer data" in md
    assert "✓" in md and "cat /opt/x/.env" in md                     # verified grounded claim
    assert "revoke_agent_token" in md and "T1552.001" in md
    assert "hallucination rate 0%" in md


def test_nis2_draft(db):
    md = nis2_draft_md(db, SID)
    assert "NIS2" in md and "early warning" in md.lower() and "DRAFT" in md
    assert "exfiltrat" in md.lower() and "ASI01" not in md            # no injection in this incident
