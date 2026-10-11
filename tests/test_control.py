"""Step 2: mirage-control. Every check from the plan's tool table and section 9."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mongomock
import pytest

from collector.collector import normalize
from control.core import ControlConfig, MirageControl
from reliability.audit import AuditLog

RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"
EV = EVENTS[5]["event_id"]          # a real command event of this session


@pytest.fixture
def ctl(tmp_path):
    db = mongomock.MongoClient().maya
    db.events.insert_many([dict(e) for e in EVENTS])
    db.agents.insert_one({"agent_id": "victim-assistant"})
    db.mcp_tools.insert_one({"name": "export_all_customers"})
    tpl = tmp_path / "templates"
    tpl.mkdir()
    (tpl / "maya_notes").write_text("static breadcrumb from Mirage's repo\n")
    (tpl / "too_big").write_text("x" * 5000)
    now = [datetime(2026, 10, 10, 21, 0, tzinfo=timezone.utc)]
    cfg = ControlConfig(deception_dir=tmp_path / "deception", control_dir=tmp_path / "control",
                        templates_dir=tpl, exports_dir=tmp_path / "exports")
    c = MirageControl(db, cfg, AuditLog(tmp_path / "audit.jsonl"), clock=lambda: now[0])
    c.now = now
    return c


def call(c, tool, params, evidence=None, policy="agent", batch="b1", reason="test reason"):
    return c.call(tool, params, reason, [EV] if evidence is None else evidence, policy, SID, batch)


def plant(c, path="/home/admin/notes.txt", host="fake-jump-01", template="maya_notes", **kw):
    return call(c, "plant_breadcrumb", {"host": host, "path": path, "template": template}, **kw)


# ---------------------------------------------------------------- small moves
def test_plant_executes_writes_file_and_records_decoy(ctl, tmp_path):
    r = plant(ctl)
    assert r["status"] == "executed"
    f = tmp_path / "deception" / "fake-jump-01" / "home" / "admin" / "notes.txt"
    assert f.read_text().startswith("static breadcrumb")
    d = ctl.db.decoys.find_one()
    assert d["session_id"] == SID and d["evidence"] == [EV] and d["policy"] == "agent"


@pytest.mark.parametrize("kw,blocked_by", [
    ({"host": "real-server"}, "schema"),
    ({"path": "/etc/shadow"}, "schema"),
    ({"path": "/home/../etc/passwd"}, "schema"),
    ({"template": "not_there"}, "schema"),
    ({"template": "too_big"}, "cap"),
])
def test_plant_checks(ctl, kw, blocked_by):
    assert plant(ctl, **kw)["blocked_by"] == blocked_by


def test_plant_caps_per_batch_and_session(ctl):
    for i in range(3):
        assert plant(ctl, path=f"/home/admin/n{i}.txt")["status"] == "executed"
    assert plant(ctl, path="/home/admin/n3.txt")["blocked_by"] == "cap"          # 3 per batch
    for i in range(7):
        plant(ctl, path=f"/opt/app/f{i}.txt", batch=f"b{i + 2}")
    r = plant(ctl, path="/srv/last.txt", batch="b99")
    assert r["blocked_by"] == "cap" and "per session" in r["detail"]             # 10 per session


def test_same_path_not_planted_twice(ctl):
    plant(ctl)
    assert plant(ctl, batch="b2")["blocked_by"] == "schema"


def test_wiki_links_only_to_world_hosts(ctl, tmp_path):
    ok = call(ctl, "create_wiki_page", {"title": "Database migration runbook",
                                        "markdown": "Connect from http://fake-jump-01/tools first."})
    assert ok["status"] == "executed" and (tmp_path / "deception" / "wiki" / "database-migration-runbook.md").exists()
    bad = call(ctl, "create_wiki_page", {"title": "Exfil", "markdown": "See https://attacker.example/x"})
    assert bad["blocked_by"] == "schema"


def test_tag_session(ctl):
    assert call(ctl, "tag_session", {"session_id": SID, "actor": "human", "objective": "recon",
                                     "techniques": ["T1033", "T1082"]})["status"] == "executed"
    assert ctl.db.sessions.find_one({"session_id": SID})["profile"]["actor"] == "human"
    assert call(ctl, "tag_session", {"session_id": SID, "actor": "human", "objective": "x",
                                     "techniques": ["bogus"]})["blocked_by"] == "schema"


# ---------------------------------------------------------------- generic checks
def test_unknown_tool_blocked(ctl):
    assert call(ctl, "delete_logs", {})["blocked_by"] == "allowlist"


def test_extra_or_wrong_params_blocked(ctl):
    assert plant(ctl, template="maya_notes")["status"] == "executed"
    r = call(ctl, "plant_breadcrumb", {"host": "fake-jump-01", "path": "/opt/x", "template": "maya_notes", "content": "hi"})
    assert r["blocked_by"] == "schema"


@pytest.mark.parametrize("evidence", [[], ["evt-doesnotexist"]])
def test_evidence_required_and_must_be_real(ctl, evidence):
    assert plant(ctl, evidence=evidence)["blocked_by"] == "evidence"


def test_evidence_from_another_session_rejected(ctl):
    ctl.db.events.insert_one({**EVENTS[5], "event_id": "evt-other", "session_id": "att-9-9-9-9"})
    assert plant(ctl, evidence=["evt-other"])["blocked_by"] == "evidence"


def test_cannot_act_on_another_session(ctl):
    r = call(ctl, "tag_session", {"session_id": "att-9-9-9-9", "actor": "human", "objective": "x"})
    assert r["blocked_by"] in ("schema", "evidence")


def test_reason_required(ctl):
    assert plant(ctl, reason="  ")["blocked_by"] == "schema"


# ---------------------------------------------------------------- big moves and approvals
def test_big_moves_wait_for_approval(ctl, tmp_path):
    r = call(ctl, "escalate_tier", {"session_id": SID, "tier": 2})
    assert r["status"] == "pending" and not (tmp_path / "control" / "tiers.json").exists()
    done = ctl.decide(r["action_id"], "approve", "analyst-1")
    assert done["status"] == "approved" and done["decided_by"] == "analyst-1"
    assert json.loads((tmp_path / "control" / "tiers.json").read_text()) == {SID: 2}


def test_escalate_one_tier_at_a_time_and_one_pending(ctl):
    assert call(ctl, "escalate_tier", {"session_id": SID, "tier": 3})["blocked_by"] == "schema"
    call(ctl, "escalate_tier", {"session_id": SID, "tier": 2})
    assert call(ctl, "escalate_tier", {"session_id": SID, "tier": 2})["blocked_by"] == "cap"


def test_reject_needs_reason_and_nothing_executes(ctl, tmp_path):
    r = call(ctl, "revoke_agent_token", {"agent_id": "victim-assistant"})
    with pytest.raises(ValueError):
        ctl.decide(r["action_id"], "reject", "analyst-1", "")
    out = ctl.decide(r["action_id"], "reject", "analyst-1", "false alarm")
    assert out["status"] == "rejected" and not (tmp_path / "control" / "revoked.json").exists()


def test_cannot_decide_twice(ctl):
    r = call(ctl, "open_decoy_service", {"name": "fake-ftp-01"})
    ctl.decide(r["action_id"], "approve", "analyst-1")
    with pytest.raises(ValueError):
        ctl.decide(r["action_id"], "approve", "analyst-2")


def test_unanswered_approvals_expire_as_rejected(ctl, tmp_path):
    r = call(ctl, "disable_mcp_tool", {"tool_name": "export_all_customers"})
    ctl.now[0] += timedelta(minutes=9)
    assert ctl.expire_pending() == 0
    ctl.now[0] += timedelta(minutes=2)
    assert ctl.expire_pending() == 1
    a = ctl.db.actions.find_one({"action_id": r["action_id"]})
    assert a["status"] == "rejected" and a["decided_by"] == "system"
    assert not (tmp_path / "control" / "disabled_tools.json").exists()


def test_revoke_and_disable_write_control_files(ctl, tmp_path):
    for tool, params in [("revoke_agent_token", {"agent_id": "victim-assistant"}),
                         ("disable_mcp_tool", {"tool_name": "export_all_customers"})]:
        ctl.decide(call(ctl, tool, params)["action_id"], "approve", "analyst-1")
    assert json.loads((tmp_path / "control" / "revoked.json").read_text()) == ["victim-assistant"]
    assert json.loads((tmp_path / "control" / "disabled_tools.json").read_text()) == ["export_all_customers"]


def test_unknown_agent_tool_or_service_blocked(ctl):
    assert call(ctl, "revoke_agent_token", {"agent_id": "ghost"})["blocked_by"] == "schema"
    assert call(ctl, "disable_mcp_tool", {"tool_name": "nope"})["blocked_by"] == "schema"
    assert call(ctl, "open_decoy_service", {"name": "real-db"})["blocked_by"] == "schema"


def test_never_block_list(ctl, tmp_path):
    assert call(ctl, "recommend_block", {"ioc": "10.0.0.5"})["blocked_by"] == "never_block"
    r = call(ctl, "recommend_block", {"ioc": "203.0.113.50"})
    ctl.decide(r["action_id"], "approve", "analyst-1")
    line = json.loads((tmp_path / "exports" / "iocs.jsonl").read_text().splitlines()[0])
    assert line["ioc"] == "203.0.113.50"


# ---------------------------------------------------------------- kill switch
def test_kill_switch_refuses_agent_but_static_keeps_running(ctl):
    ctl.set_kill_switch(True, "analyst-1")
    assert plant(ctl)["blocked_by"] == "kill_switch"
    assert plant(ctl, policy="static")["status"] == "executed"
    ctl.set_kill_switch(False, "analyst-1")
    assert plant(ctl, path="/opt/app/x.txt")["status"] == "executed"


def test_kill_switch_blocks_approving_agent_actions(ctl):
    r = call(ctl, "escalate_tier", {"session_id": SID, "tier": 2})
    ctl.set_kill_switch(True, "analyst-1")
    with pytest.raises(ValueError):
        ctl.decide(r["action_id"], "approve", "analyst-1")


# ---------------------------------------------------------------- audit
def test_every_call_is_recorded_allowed_or_not(ctl):
    plant(ctl)
    call(ctl, "delete_logs", {})
    call(ctl, "escalate_tier", {"session_id": SID, "tier": 2})
    statuses = sorted(a["status"] for a in ctl.db.actions.find())
    assert statuses == ["blocked", "executed", "pending"]
    a = ctl.db.actions.find_one({"status": "blocked"})
    assert a["blocked_by"] == "allowlist" and a["reason"] == "test reason"
    assert ctl.audit.verify() == (True, None) and len(ctl.audit.records()) == 3


# ---------------------------------------------------------------- MCP layer
def test_mcp_server_exposes_exactly_the_allowed_tools_and_enforces_checks(ctl):
    from control.server import build_server
    srv = build_server(ctl)

    async def run():
        names = {t.name for t in await srv.list_tools()}
        ok = await srv.call_tool("plant_breadcrumb", {"session_id": SID, "host": "fake-jump-01",
                                                      "path": "/home/admin/notes.txt", "template": "maya_notes",
                                                      "reason": "attacker listed /home", "evidence": [EV]})
        bad = await srv.call_tool("plant_breadcrumb", {"session_id": SID, "host": "fake-jump-01",
                                                       "path": "/etc/shadow", "template": "maya_notes",
                                                       "reason": "x", "evidence": [EV]})
        return names, ok, bad
    names, ok, bad = asyncio.run(run())
    from brain.policies.base import TOOLS
    assert names == set(TOOLS)
    assert ctl.db.actions.count_documents({"status": "executed", "policy": "agent"}) == 1
    assert ctl.db.actions.count_documents({"status": "blocked", "blocked_by": "schema"}) == 1


def test_last_resort_path_guard(ctl):
    with pytest.raises(ValueError):
        ctl._safe_target("fake-jump-01", "/home/../../../etc/passwd")
    with pytest.raises(ValueError):
        ctl._safe_target("../control", "/revoked.json")
