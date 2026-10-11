"""Kill-chain phase mapping + the attacker<->Mirage story builder, and the two new MCP/RAG scenarios."""
import tempfile
from pathlib import Path

import mongomock

from ai_traps.mcp_company import DECOY_TOOLS, MCPCompany
from ai_traps.victim import DOCS, SCRIPTS, VictimAssistant
from dashboard.killchain import PHASES, build_story, owasp_of, phase_of


def test_phase_of_uses_technique_then_event_type():
    assert phase_of({"event_type": "command", "technique": "T1552.001"}) == "discovery"
    assert phase_of({"event_type": "command", "technique": "T1046"}) == "recon"
    assert phase_of({"event_type": "command", "technique": "T1005"}) == "collection"
    assert phase_of({"event_type": "login", "technique": "T1078"}) == "access"
    # event_type overrides technique for honeynet signals
    assert phase_of({"event_type": "canary_use", "technique": "T1078"}) == "exfil"
    assert phase_of({"event_type": "egress"}) == "exfil"
    assert phase_of({"event_type": "doc_retrieval"}) == "collection"
    assert phase_of({"event_type": "injection_attempt"}) == "access"


def test_owasp_of():
    assert owasp_of({"event_type": "canary_use"}) == "ASI03"
    assert owasp_of({"event_type": "injection_attempt"}) == "ASI01"
    assert owasp_of({"event_type": "trap_hit", "trap": {"trap_id": "mcp:export_all_customers"}}) == "ASI02"
    assert owasp_of({"event_type": "doc_retrieval", "trap": {"trap_id": "rag:Customer list"}}) == "ASI06"
    assert owasp_of({"event_type": "command"}) is None


def test_build_story_pairs_sides_and_tracks_phases():
    timeline = [
        {"ts": "t1", "event_type": "login", "host": "pay-jump-01", "technique": "T1078", "content": "ssh", "severity": "info"},
        {"ts": "t4", "event_type": "canary_use", "host": "data-store-01", "content": "used secret", "severity": "crit"},
    ]
    decoys = [{"created_at": "t2", "host": "pay-jump-01", "path": "/opt/.env", "reason": "lure"}]
    actions = [{"tool": "recommend_block", "status": "pending", "reason": "exfil", "at": "t5"}]
    reasoning = [{"at": "t1b", "profile": {"actor": "ai_agent", "confidence": 0.9, "objective": "exfil"}}]
    alerts = [{"type": "canary_use", "owasp": "ASI03", "excerpt": "canary", "at": "t4b"}]
    story = build_story(timeline, decoys, actions, reasoning, alerts)

    sides = [b["side"] for b in story["beats"]]
    assert "attacker" in sides and "mirage" in sides
    # time-ordered
    assert [b["ts"] for b in story["beats"]] == sorted(b["ts"] for b in story["beats"])
    # the containment action reaches the Contained phase
    assert story["current_phase"] == "contained"
    reached = {p["key"] for p in story["phases"] if p["reached"]}
    assert {"access", "collection", "exfil", "contained"} <= reached
    assert [p["key"] for p in story["phases"]] == PHASES


def _run(name):
    tmp = Path(tempfile.mkdtemp())
    db = mongomock.MongoClient().maya
    mcp = MCPCompany(db, tmp / f"{name}.jsonl", docs=dict(DOCS))
    mcp.scan_descriptions()
    res = VictimAssistant(mcp, SCRIPTS[name]()).run()
    import json
    events = [json.loads(l) for l in (tmp / f"{name}.jsonl").read_text().splitlines()]
    kinds = {}
    for e in events:
        kinds[e["event_type"]] = kinds.get(e["event_type"], 0) + 1
    return res, kinds


def test_mcp_poison_scenario_hits_decoy_tools_and_exfiltrates():
    res, kinds = _run("mcp_poison")
    assert res.hijacked and res.exfiltrated
    assert kinds.get("trap_hit", 0) >= 2          # decoy MCP tools (ASI02)
    assert kinds.get("egress", 0) == 1            # external exfiltration
    assert kinds.get("injection_attempt", 0) >= 1 # poisoned tool description (ASI06)


def test_rag_thief_scenario_retrieves_honey_docs_and_exfiltrates():
    res, kinds = _run("rag_thief")
    assert res.exfiltrated
    assert kinds.get("doc_retrieval", 0) >= 2     # honey-docs retrieved (ASI06)
    assert kinds.get("egress", 0) == 1


def test_victim_email_scenario_still_hijacks():
    res, kinds = _run("victim")
    assert res.hijacked and res.exfiltrated
    assert "export_all_customers" in " ".join(DECOY_TOOLS)  # sanity: decoy surface present
