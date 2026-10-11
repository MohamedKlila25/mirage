"""Step 1: shared policy interface and the static baseline (on the real Cowrie session)."""
import json
from pathlib import Path

import mongomock
import pytest

from brain.policies.base import TOOLS, Action, Policy, SessionState
from brain.policies.static import StaticBreadcrumb, StaticConfig, StaticPolicy
from brain.session import load_session_state
from collector.collector import normalize

RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"
CFG = StaticConfig(breadcrumbs=[
    StaticBreadcrumb("fake-jump-01", "/home/admin/notes.txt", "maya_notes"),
    StaticBreadcrumb("fake-jump-01", "/opt/app/config.json", "maya_db_config"),
    StaticBreadcrumb("fake-db-01", "/root/backup.txt", "maya_backup"),
], escalate_every=3)


def tools(actions):
    return [a.tool for a in actions]


def test_tool_risk_levels_match_the_plan():
    assert {t for t, r in TOOLS.items() if r == "approval"} == {
        "escalate_tier", "open_decoy_service", "recommend_block", "revoke_agent_token", "disable_mcp_tool"}


def test_policy_cannot_invent_tools():
    class Rogue(Policy):
        name = "rogue"
        def decide(self, state, new_events):
            return [self._act("delete_everything", {}, "x", [])]
    with pytest.raises(ValueError):
        Rogue().decide(SessionState(SID), [])


def test_first_login_plants_that_hosts_fixed_breadcrumbs_once():
    p = StaticPolicy(CFG)
    acts = p.decide(SessionState(SID, events=EVENTS), EVENTS)
    plants = [a for a in acts if a.tool == "plant_breadcrumb"]
    assert [a.params["path"] for a in plants] == ["/home/admin/notes.txt", "/opt/app/config.json"]
    assert all(a.policy == "static" and a.evidence for a in plants)
    login_id = next(e["event_id"] for e in EVENTS if e["event_type"] == "login")
    assert plants[0].evidence == [login_id]


def test_already_planted_is_not_planted_again():
    planted = [{"host": "fake-jump-01", "path": "/home/admin/notes.txt"}, {"host": "fake-jump-01", "path": "/opt/app/config.json"}]
    acts = StaticPolicy(CFG).decide(SessionState(SID, events=EVENTS, planted=planted), EVENTS)
    assert "plant_breadcrumb" not in tools(acts)


def test_escalates_one_tier_after_n_commands_and_waits_if_pending():
    st = SessionState(SID, events=EVENTS, tier=1)          # 6 commands, escalate_every=3 -> wants tier 3
    acts = StaticPolicy(CFG).decide(st, [])
    esc = [a for a in acts if a.tool == "escalate_tier"]
    assert len(esc) == 1 and esc[0].params["tier"] == 2      # one step at a time
    st.pending_approvals = [{"tool": "escalate_tier"}]
    assert "escalate_tier" not in tools(StaticPolicy(CFG).decide(st, []))


def test_never_above_max_tier():
    many = EVENTS * 20
    acts = StaticPolicy(CFG).decide(SessionState(SID, events=many, tier=3), [])
    assert "escalate_tier" not in tools(acts)


def test_observes_when_nothing_scheduled():
    st = SessionState(SID, events=EVENTS[:3], tier=1)
    new = [e for e in EVENTS[:3] if e["event_type"] != "login"]
    assert tools(StaticPolicy(CFG).decide(st, new)) == ["observe"]


def test_session_state_loaded_from_mongo():
    db = mongomock.MongoClient().maya
    db.events.insert_many([dict(e) for e in EVENTS])
    db.sessions.insert_one({"session_id": SID, "tier": 2})
    db.decoys.insert_one({"session_id": SID, "host": "fake-jump-01", "path": "/home/admin/notes.txt"})
    db.actions.insert_one({"session_id": SID, "tool": "escalate_tier", "status": "pending", "ts": "1"})
    st = load_session_state(db, SID)
    assert st.tier == 2 and len(st.events) == len(EVENTS) and st.has_pending("escalate_tier")
    assert st.hosts_logged_in == ["fake-jump-01"] and len(st.commands) == 6
