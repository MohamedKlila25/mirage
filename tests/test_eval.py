"""Evaluation metrics: reliability/detection from the db, and the static-vs-agent comparison table."""
import mongomock

from eval.metrics import compare_table, detection_metrics, operational_metrics, reliability_metrics


def _db():
    db = mongomock.MongoClient().maya
    db.actions.insert_many([
        {"risk": "auto", "status": "executed", "evidence": ["e1"]},
        {"risk": "approval", "status": "pending", "evidence": ["e2"]},
        {"risk": "auto", "status": "blocked", "blocked_by": "evidence", "evidence": ["bad"]},
        {"risk": "auto", "status": "blocked", "blocked_by": "schema", "evidence": ["e3"]},
    ])
    db.batches.insert_many([{"latency_s": 2.0}, {"latency_s": 4.0}])
    db.events.insert_many([
        {"event_type": "command", "ts": "2026-10-10T20:00:00Z", "trap": {"is_trap": False}},
        {"event_type": "trap_hit", "ts": "2026-10-10T20:00:05Z", "trap": {"is_trap": True}},
    ])
    db.strategies.insert_one({"at": "2026-10-10T20:00:08Z"})
    return db


def test_reliability_metrics():
    m = reliability_metrics(_db())
    assert m["auto_actions"] == 1 and m["approvals_requested"] == 1
    assert m["actions_blocked"] == 2 and m["bad_citations"] == 1
    assert m["citation_integrity"] == 0.75                     # 1 bad citation of 4 actions that cited evidence
    assert m["human_in_loop"] == 0.5 and m["avg_latency_s"] == 3.0


def test_detection_metrics():
    d = detection_metrics(_db())
    assert d["time_to_detect_s"] == 3.0 and d["alert_precision"] == 1.0   # first trap 20:00:05 -> strategy 20:00:08


def test_operational_metrics_mttd_mtta_trap_f1():
    db = mongomock.MongoClient().maya
    sid = "att-1"
    db.events.insert_many([
        {"session_id": sid, "event_type": "command", "ts": "2026-10-10T20:00:00Z", "trap": {"is_trap": False}},
        {"session_id": sid, "event_type": "trap_hit", "ts": "2026-10-10T20:00:04Z",
         "trap": {"is_trap": True, "trap_id": "mcp:export_all_customers"}},
        {"session_id": sid, "event_type": "doc_retrieval", "ts": "2026-10-10T20:00:06Z",
         "trap": {"is_trap": True, "trap_id": "rag:Customer list"}},
    ])
    db.strategies.insert_one({"session_id": sid, "at": "2026-10-10T20:00:03Z"})     # detect at +3s
    db.alerts.insert_one({"session_id": sid, "at": "2026-10-10T20:00:05Z"})         # alert at +5s
    db.decoys.insert_many([{"session_id": sid, "touched_by": ["e"]},
                           {"session_id": sid, "touched_by": []}])
    db.world_model.insert_one({"_id": "current", "mcp_decoy_tools": ["export_all_customers"], "honey_docs": ["Customer list"]})
    m = operational_metrics(db)
    assert m["mttd_s"] == 3.0 and m["mtta_s"] == 5.0
    assert 0 < m["trap_activation_rate"] <= 1.0
    assert m["precision"] == 1.0 and m["recall"] is not None and m["f1_score"] is not None


def test_scenarios_breakdown_is_agent_only_and_sorted_by_difficulty():
    from dashboard.api import _scenarios
    db = mongomock.MongoClient().maya
    db.runs.insert_many([
        {"policy": "static", "attacker": "data_thief", "canary_uses": 0, "trap_hits": 0, "decoys_touched": 0, "techniques_observed": 5},
        {"policy": "agent", "attacker": "apt", "canary_uses": 10, "trap_hits": 1, "decoys_touched": 2, "techniques_observed": 6, "injection_alerts": 0},
        {"policy": "agent", "attacker": "evasive", "canary_uses": 0, "trap_hits": 3, "decoys_touched": 0, "techniques_observed": 0, "injection_alerts": 1},
        {"policy": "agent", "attacker": "victim", "canary_uses": 0, "trap_hits": 1, "decoys_touched": 0, "techniques_observed": 0, "injection_alerts": 1},
    ])
    s = _scenarios(db)
    assert all(x["attacker"] != "data_thief" or x["runs"] for x in s)   # static run ignored
    labels = {x["attacker"] for x in s}
    assert "apt" in labels and "evasive" in labels and all(x["defended"] for x in s)
    assert s[0]["difficulty"] == "hard"                                # hard scenarios first


def test_evasive_scenario_tries_to_blind_then_exfiltrates(tmp_path):
    import json
    from pathlib import Path
    from ai_traps.mcp_company import MCPCompany
    from ai_traps.victim import DOCS, SCRIPTS, VictimAssistant
    db = mongomock.MongoClient().maya
    mcp = MCPCompany(db, tmp_path / "mcp.jsonl", docs=dict(DOCS))
    mcp.scan_descriptions()
    res = VictimAssistant(mcp, SCRIPTS["evasive"]()).run()
    kinds = {}
    for l in Path(mcp.trap_log).read_text().splitlines():
        e = json.loads(l); kinds[e["event_type"]] = kinds.get(e["event_type"], 0) + 1
    assert res.hijacked and res.exfiltrated
    assert kinds.get("trap_hit", 0) >= 2            # disable_audit_log (evasion) + decoy tools
    assert kinds.get("doc_retrieval", 0) >= 1 and kinds.get("egress", 0) == 1


def test_blended_auto_scenario_mixes_vectors(tmp_path):
    import json
    from pathlib import Path
    from ai_traps.mcp_company import MCPCompany
    from ai_traps.victim import DOCS, SCRIPTS, VictimAssistant
    db = mongomock.MongoClient().maya
    mcp = MCPCompany(db, tmp_path / "mcp.jsonl", docs=dict(DOCS))
    mcp.scan_descriptions()
    res = VictimAssistant(mcp, SCRIPTS["auto_blend"]()).run()
    kinds = {}
    for l in Path(mcp.trap_log).read_text().splitlines():
        e = json.loads(l); kinds[e["event_type"]] = kinds.get(e["event_type"], 0) + 1
    assert res.hijacked and res.exfiltrated                          # mixed: MCP decoy + exfil
    assert kinds.get("doc_retrieval", 0) >= 1                        # RAG (ASI06)
    assert kinds.get("trap_hit", 0) >= 1 and kinds.get("egress", 0) == 1


def test_audit_verified(tmp_path):
    from reliability.audit import AuditLog
    a = AuditLog(tmp_path / "audit.jsonl")
    a.append("x", v=1)
    assert reliability_metrics(_db(), tmp_path / "audit.jsonl")["audit_verified"] is True


def test_compare_table_shapes_static_vs_agent():
    runs = [
        {"policy": "static", "seed": 1, "commands": 20, "decoys_planted": 0, "decoys_touched": 1,
         "techniques_observed": 4, "hosts_entered": 1, "canary_uses": 0, "trap_hits": 0, "citation_integrity": 1.0},
        {"policy": "agent", "seed": 1, "commands": 30, "decoys_planted": 3, "decoys_touched": 3,
         "techniques_observed": 6, "hosts_entered": 2, "canary_uses": 5, "trap_hits": 1, "citation_integrity": 0.95},
    ]
    table = compare_table(runs)
    assert table[0] == ("metric", "static", "agent")
    row = {r[0]: (r[1], r[2]) for r in table[1:]}
    assert row["dwell (cmds)"] == ("20", "30") and row["decoys planted"] == ("0", "3")
    assert row["ATT&CK techniques"] == ("4", "6")
