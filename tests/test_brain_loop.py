"""The brain loop runs the active policy through mirage-control only; kill switch forces static."""
import json
from datetime import datetime, timezone
from pathlib import Path

import mongomock
import pytest

from brain.loop import BrainConfig, BrainLoop
from brain.policies.base import Action, Policy, SessionState
from brain.policies.static import StaticBreadcrumb, StaticConfig, StaticPolicy
from collector.collector import normalize
from control.core import ControlConfig, MirageControl
from reliability.audit import AuditLog

RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"


class SpyAgent(Policy):
    """Stands in for the real AgentPolicy (Phase 3): records it was asked, plants tailored content."""
    name = "agent"
    uses_llm = True
    max_actions = 3

    def __init__(self):
        self.calls = 0

    def decide(self, state, new_events):
        self.calls += 1
        last = new_events[-1]["event_id"]
        return [Action("plant_breadcrumb",
                       {"host": "fake-jump-01", "path": "/opt/payouts/.env",
                        "content": "DB_HOST=fake-db-01\nDB_PASSWORD={{canary:password_1}}\n"},
                       "attacker probed /opt/payouts", [last], "agent")]


@pytest.fixture
def brain(tmp_path):
    db = mongomock.MongoClient().maya
    db.events.insert_many([dict(e) for e in EVENTS])
    db.world_model.insert_one({"_id": "current", "world_hosts": ["fake-jump-01", "fake-db-01", "wiki"]})
    (tmp_path / "templates").mkdir()
    manifest = tmp_path / "deception" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"fake-jump-01": ["/opt/payouts/.env"]}))
    cfg = ControlConfig(deception_dir=tmp_path / "deception", control_dir=tmp_path / "control",
                        templates_dir=tmp_path / "templates", exports_dir=tmp_path / "exports", manifest_path=manifest)
    control = MirageControl(db, cfg, AuditLog(tmp_path / "audit.jsonl"))
    static = StaticPolicy(StaticConfig(breadcrumbs=[], escalate_every=3))   # frozen-env baseline: no per-attacker planting
    agent = SpyAgent()
    clock = lambda: datetime(2026, 10, 10, 20, 4, 40, tzinfo=timezone.utc)   # ~35 s after the recorded session
    loop = BrainLoop(db, control, {"static": static, "agent": agent},
                     BrainConfig(batch_size=100, batch_wait_s=600), clock=clock)
    return db, control, loop, agent, tmp_path


def test_defaults_to_static_and_runs_it_through_control(brain):
    db, control, loop, agent, _ = brain
    assert loop.active_policy_name() == "static"
    [r] = loop.poll_once()
    assert r["policy"] == "static" and agent.calls == 0
    # static baseline with no breadcrumbs: it escalates on schedule (6 cmds) and observes -> all via control
    assert db.actions.count_documents({"policy": "static"}) >= 1
    assert db.events.count_documents({"brain_at": None}) == 0          # batch marked processed
    assert control.audit.verify() == (True, None)


def test_switch_to_agent_routes_actions_through_control(brain):
    db, control, loop, agent, tmp = brain
    loop.set_policy("agent", "analyst-1")
    assert loop.active_policy_name() == "agent"
    [r] = loop.poll_once()
    assert r["policy"] == "agent" and agent.calls == 1 and r["executed"] == 1
    d = db.decoys.find_one({"policy": "agent"})
    assert d["path"] == "/opt/payouts/.env" and d["canaries"] == ["canary:password_1"]
    assert (tmp / "deception" / "fake-jump-01" / "opt" / "payouts" / ".env").exists()


def test_kill_switch_forces_static_even_when_agent_is_selected(brain):
    db, control, loop, agent, _ = brain
    loop.set_policy("agent", "analyst-1")
    control.set_kill_switch(True, "analyst-1")
    assert loop.active_policy_name() == "static"
    loop.poll_once()
    assert agent.calls == 0                                             # the agent never ran
    assert db.actions.count_documents({"policy": "agent"}) == 0


def test_agent_action_is_refused_by_control_if_kill_switch_flips_mid_decision(brain):
    db, control, loop, agent, _ = brain
    # force the agent to run, then turn the kill switch on before its action reaches control
    db.control.insert_one({"_id": "active_policy", "policy": "agent"})
    orig = loop.active_policy_name
    loop.active_policy_name = lambda: "agent"                            # pretend it was agent this tick
    control.set_kill_switch(True, "analyst-1")
    loop.poll_once()
    assert db.actions.find_one({"policy": "agent"})["blocked_by"] == "kill_switch"
    loop.active_policy_name = orig


def test_llm_budget_stops_the_agent(brain):
    db, control, loop, agent, _ = brain
    loop.set_policy("agent", "analyst-1")
    db.sessions.insert_one({"session_id": SID, "llm_calls": 20})
    [r] = loop.poll_once()
    assert r["skipped"] == "llm budget exhausted" and agent.calls == 0
    assert db.events.count_documents({"brain_at": None}) == 0           # still marked, not reprocessed forever


def test_policy_failure_leaves_events_for_retry(brain):
    db, control, loop, agent, _ = brain
    class Boom(Policy):
        name = "agent"
        uses_llm = True
        def decide(self, state, new_events):
            raise RuntimeError("ThrottlingException")
    loop.policies["agent"] = Boom()
    loop.set_policy("agent", "analyst-1")
    loop.poll_once()
    assert db.events.count_documents({"brain_at": None}) == len(EVENTS)
    assert db.errors.find_one()["error"].startswith("RuntimeError")


def test_only_batches_when_ready(brain):
    db, control, loop, agent, _ = brain
    db.events.delete_many({"event_type": "session_end"})
    loop.cfg = BrainConfig(batch_size=100, batch_wait_s=600)
    assert loop.ready_sessions() == []                                  # not enough, not waited, no disconnect
