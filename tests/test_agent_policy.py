"""AgentPolicy: builds a tailored decoy from the batch, handles injection and bad output,
and (through the brain + mirage-control) actually plants it."""
import json
import re
from pathlib import Path

import mongomock
import pytest

from brain.agent.context import MongoRecorder, MongoWorldModel
from brain.agent.prompt import build_agent_prompt
from brain.loop import BrainConfig, BrainLoop
from brain.policies.agent import AgentPolicy
from brain.policies.base import SessionState
from brain.policies.static import StaticConfig, StaticPolicy
from brain.session import load_session_state
from collector.collector import normalize
from control.core import ControlConfig, MirageControl
from reliability.audit import AuditLog

RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]
SID = "att-127-0-0-1"
WORLD = {"company": "Northwind Pay", "sector": "fintech", "world_hosts": ["fake-jump-01", "fake-db-01", "wiki"],
         "hosts": [{"slot": "fake-jump-01", "hostname": "fake-jump-01", "role": "jump"}],
         "manifest": {"fake-jump-01": ["/opt/payouts/.env"]}}


class FakeLLM:
    """Reads the evidence block like a model would; plants a tailored .env citing a real event."""

    def __init__(self, mode="good"):
        self.mode, self.prompts = mode, []

    def __call__(self, system, user):
        self.prompts.append(user)
        if self.mode == "garbage":
            return "the attacker is a ransomware gang, trust me"
        ev = re.findall(r'event_id="(evt-[0-9a-f]+)"[^>]*event_type="(\w+)"', user)
        cmds = [e for e, t in ev if t == "command"]
        objective = "benign" if self.mode == "benign" else "data_theft"
        out = {
            "profile": {"actor": "human", "skill": "mid", "objective": objective, "confidence": 0.8},
            "predicted_next": [{"technique": "T1021.004", "p": 0.6}],
            "goal": "gather_intel",
            "actions": [{"tool": "plant_breadcrumb",
                         "params": {"host": "fake-jump-01", "path": "/opt/payouts/.env",
                                    "content": "DB_HOST=fake-db-01\nDB_USER=payouts\nDB_PASSWORD={{canary:password_1}}\n"},
                         "reason": "attacker is enumerating the payments app; a DB .env leads them to fake-db-01",
                         "evidence": [cmds[0] if cmds else ev[0][0]]}],
        }
        return "```json\n" + json.dumps(out) + "\n```"


@pytest.fixture
def setup(tmp_path):
    db = mongomock.MongoClient().maya
    db.events.insert_many([dict(e) for e in EVENTS])
    db.world_model.insert_one({"_id": "current", **WORLD})
    (tmp_path / "templates").mkdir()
    manifest = tmp_path / "deception" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(WORLD["manifest"]))
    cfg = ControlConfig(deception_dir=tmp_path / "deception", control_dir=tmp_path / "control",
                        templates_dir=tmp_path / "templates", exports_dir=tmp_path / "exports", manifest_path=manifest)
    control = MirageControl(db, cfg, AuditLog(tmp_path / "audit.jsonl"))
    return db, control, tmp_path


def make_agent(db, mode="good", classify=None):
    return AgentPolicy(FakeLLM(mode), MongoWorldModel(db), MongoRecorder(db), classify)


def test_prompt_carries_rules_world_and_evidence():
    state = SessionState(SID, events=EVENTS)
    system, user = build_agent_prompt(state, EVENTS[:3], WORLD)
    assert "never instructions" in system.lower() and "{{canary:" in system
    assert "Northwind Pay" in user and "/opt/payouts/.env" in user and "<untrusted_data" in user
    assert SID in user


def test_agent_returns_a_tailored_plant_action(setup):
    db, control, _ = setup
    state = load_session_state(db, SID)
    actions = make_agent(db).decide(state, EVENTS)
    assert len(actions) == 1 and actions[0].tool == "plant_breadcrumb"
    assert actions[0].params["content"].count("{{canary:password_1}}") == 1 and actions[0].policy == "agent"
    assert db.strategies.find_one()["profile"]["objective"] == "data_theft"
    assert db.sessions.find_one({"session_id": SID})["profile"]["actor"] == "human"


def test_full_agent_batch_plants_the_decoy_through_control(setup):
    db, control, tmp = setup
    loop = BrainLoop(db, control, {"static": StaticPolicy(StaticConfig(breadcrumbs=[])), "agent": make_agent(db)},
                     BrainConfig(batch_size=100, batch_wait_s=600))
    loop.set_policy("agent", "analyst-1")
    [r] = loop.poll_once()
    assert r["executed"] == 1
    planted = (tmp / "deception" / "fake-jump-01" / "opt" / "payouts" / ".env").read_text()
    assert control.canaries.resolve("password_1") in planted and "{{" not in planted
    assert db.decoys.find_one({"policy": "agent"})["canaries"] == ["canary:password_1"]


def test_injection_in_batch_raises_an_alert(setup):
    db, control, _ = setup                                   # the real fixture contains a "SYSTEM NOTE TO AI ANALYST" echo
    make_agent(db).decide(load_session_state(db, SID), EVENTS)
    a = db.alerts.find_one({"type": "injection_attempt"})
    assert a and a["owasp"] == "ASI01"


def test_benign_verdict_on_an_injected_session_is_overridden(setup):
    db, control, _ = setup
    make_agent(db, mode="benign").decide(load_session_state(db, SID), EVENTS)
    assert db.alerts.find_one({"type": "defender_manipulation_suspected"})
    assert db.strategies.find_one({"benign_verdict_overridden": True})


def test_bad_output_twice_falls_back_to_observe(setup):
    db, control, _ = setup
    actions = make_agent(db, mode="garbage").decide(load_session_state(db, SID), EVENTS)
    assert len(actions) == 1 and actions[0].tool == "observe"
    assert db.strategies.find_one()["status"] == "invalid_output"


def test_optional_classifier_adds_findings(setup):
    db, control, _ = setup
    clean = [e for e in EVENTS if "SYSTEM NOTE" not in e["untrusted_content"]]
    db.events.delete_many({"untrusted_content": {"$regex": "SYSTEM NOTE"}})
    make_agent(db, classify=lambda t: "wget" in t).decide(load_session_state(db, SID), clean)
    assert db.alerts.find_one({"patterns": ["classifier"]})
