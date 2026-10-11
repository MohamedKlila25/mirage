"""Defender service end to end: real Cowrie log -> collector -> MongoDB -> defender (fake LLM) -> results."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mongomock
import pytest

from collector.collector import Collector, MongoSink
from defender.service import DefenderConfig, DefenderService
from reliability import AuditLog, PolicyConfig, ReliabilityGate, build_prompt
from scenario import BENIGN_EVENTS

FIXTURE = Path(__file__).parent / "fixtures" / "cowrie_real_session.json"
SID = "att-127-0-0-1"
EV = re.compile(r'<untrusted_data event_id="(evt-[0-9a-f]+)"[^>]*event_type="(\w+)"[^>]*>(.*?)</untrusted_data>')

UNAME_RULE = """
title: System discovery with uname
logsource: {product: linux, service: cowrie}
detection:
  sel:
    event_type: command
    untrusted_content|startswith: 'uname'
  condition: sel
"""
WHOAMI_RULE = UNAME_RULE.replace("uname", "whoami")   # benign admins run whoami too -> must be rejected


class FakeLLM:
    """Reads the evidence block like a real model would and answers with grounded JSON."""

    def __init__(self, mode="good"):
        self.mode, self.calls = mode, []

    def __call__(self, system, user):
        self.calls.append(user)
        if self.mode == "error":
            raise RuntimeError("ThrottlingException")
        sid = re.search(r"Session to analyze: (\S+)", user).group(1)
        evs = [(i, t, c) for i, t, c in EV.findall(user)]
        by = lambda pred: [i for i, t, c in evs if pred(t, c)]
        login = by(lambda t, c: t == "login")
        whoami = by(lambda t, c: c == "whoami")
        uname = by(lambda t, c: c.startswith("uname"))
        cmds = by(lambda t, c: t == "command")
        out = {
            "session_id": sid,
            "profile": {"actor": "human", "skill": "low", "objective": "reconnaissance",
                        "confidence": 0.8 if self.mode == "good" else 0.3, "evidence": cmds[:3] or login},
            "attack_techniques": ([{"id": "T1078", "confidence": 0.9, "evidence": login}] if login else []) +
                                 ([{"id": "T1033", "confidence": 0.8, "evidence": whoami}] if whoami else []) +
                                 ([{"id": "T1082", "confidence": 0.8, "evidence": uname}] if uname else []),
            "goal": "gather_intel",
            "honeynet_actions": [{"tool": "plant_breadcrumb", "params": {"type": "fake_db_dump", "host": "fake-jump-01"},
                                  "reason": "keep the attacker engaged", "evidence": cmds[:1] or login}],
            "proposals": [],
        }
        if uname:
            out["proposals"].append({"type": "sigma_rule", "payload": {"yaml": UNAME_RULE}, "technique": "T1082",
                                     "confidence": 0.8, "evidence": uname, "rationale": "system discovery on a decoy"})
        if whoami:
            out["proposals"].append({"type": "sigma_rule", "payload": {"yaml": WHOAMI_RULE}, "technique": "T1033",
                                     "confidence": 0.8, "evidence": whoami, "rationale": "user discovery"})
        return json.dumps(out)


class FakeActuator:
    def __init__(self, ok=True):
        self.ok, self.sent = ok, []

    def execute(self, action):
        self.sent.append(action)
        return (True, "done") if self.ok else (False, "ConnectionRefused")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("MIRAGE_KILL_SWITCH", raising=False)
    d = tmp_path / "decoys" / "fake-jump-01" / "log" / "cowrie"
    d.mkdir(parents=True)
    (d / "cowrie.json").write_text(FIXTURE.read_text())
    db = mongomock.MongoClient().maya
    Collector(tmp_path / "decoys", MongoSink(db)).poll_once()
    now = [datetime(2026, 10, 10, 20, 4, 30, tzinfo=timezone.utc)]  # shortly after the recorded session
    pcfg = PolicyConfig(kill_switch_file=str(tmp_path / "kill"))
    gate = ReliabilityGate(pcfg, AuditLog(tmp_path / "audit.jsonl"), BENIGN_EVENTS)

    def make(llm=None, actuator=None, **cfg):
        return DefenderService(db, gate, llm or FakeLLM(), DefenderConfig(**cfg), actuator or FakeActuator(),
                               clock=lambda: now[0])
    return db, gate, make, now, tmp_path


def test_prompt_tells_the_llm_which_session():
    _, user = build_prompt([], session_id="att-1-2-3-4")
    assert "Session to analyze: att-1-2-3-4" in user


def test_full_chain_on_real_cowrie_session(env):
    db, gate, make, _, _ = env
    act = FakeActuator()
    svc = make(actuator=act)
    [r] = svc.poll_once()
    assert r["status"] == "ok" and r["escalate"] and r["auto_actions"] == 0   # session holds an injection
    assert db.events.count_documents({"analyzed_at": None}) == 0
    s = db.strategies.find_one()
    verified = {c["ref"] for c in s["claims"] if c["status"] == "verified"}
    assert {"T1078", "T1033", "T1082"} <= verified                      # LLM claims checked on real events
    props = {p["technique"]: p for p in db.proposals.find()}
    assert props["T1082"]["status"] == "pending_approval"               # validated rule waits for analyst
    assert props["T1082"]["validation"]["benign_hits"] == []
    assert "T1033" not in props                                         # whoami rule fires on benign logs: rejected
    assert any("false positives" in x["reasons"][0] for x in s["rejected"])
    assert db.alerts.find_one({"type": "injection_attempt"})            # the real injected echo was caught
    assert act.sent == []


def test_injection_in_session_blocks_automatic_actions(env):
    db, gate, make, _, _ = env
    act = FakeActuator()
    make(actuator=act).poll_once()
    assert act.sent == []                                               # recorded session contains an injection
    assert db.escalations.find_one({"session_id": SID})["pending_actions"][0]["tool"] == "plant_breadcrumb"


def test_clean_session_runs_allowed_action(env):
    db, gate, make, _, _ = env
    db.events.delete_many({"untrusted_content": {"$regex": "SYSTEM NOTE"}})
    act = FakeActuator()
    make(actuator=act).poll_once()
    assert [a["tool"] for a in act.sent] == ["plant_breadcrumb"]
    assert db.actions.find_one()["executed"] is True


def test_batching_waits_for_enough_events(env):
    db, gate, make, now, _ = env
    db.events.delete_many({"event_type": "session_end"})
    svc = make(batch_size=100, batch_wait_s=600)
    assert svc.ready_sessions() == []                                   # few events, not waited long enough
    now[0] += timedelta(minutes=11)
    assert svc.ready_sessions() == [SID]


def test_session_end_triggers_batch(env):
    db, gate, make, _, _ = env
    assert make(batch_size=100, batch_wait_s=600).ready_sessions() == [SID]


def test_no_new_events_no_llm_call(env):
    db, gate, make, _, _ = env
    llm = FakeLLM()
    svc = make(llm=llm)
    svc.poll_once()
    svc.poll_once()
    assert len(llm.calls) == 1


def test_llm_failure_keeps_events_for_retry(env):
    db, gate, make, _, _ = env
    make(llm=FakeLLM("error")).poll_once()
    assert db.events.count_documents({"analyzed_at": None}) == db.events.count_documents({})
    assert db.errors.find_one()["error"].startswith("RuntimeError")
    make().poll_once()
    assert db.events.count_documents({"analyzed_at": None}) == 0


def test_budget_cap_stops_llm_calls(env):
    db, gate, make, _, _ = env
    db.sessions.insert_one({"session_id": SID, "llm_calls": 5})
    llm = FakeLLM()
    [r] = make(llm=llm, max_llm_calls_per_session=5).poll_once()
    assert r["skipped"] == "budget exhausted" and llm.calls == []
    assert "budget" in db.escalations.find_one()["reasons"][0]


def test_kill_switch_means_no_llm_call(env, monkeypatch):
    db, gate, make, _, _ = env
    monkeypatch.setenv("MIRAGE_KILL_SWITCH", "1")
    llm = FakeLLM()
    make(llm=llm).poll_once()
    assert llm.calls == [] and db.events.count_documents({"analyzed_at": None}) > 0


def test_analyst_decision_is_kept_when_rule_is_proposed_again(env):
    db, gate, make, _, _ = env
    svc = make()
    svc.poll_once()
    pid = db.proposals.find_one({"technique": "T1082"})["proposal_id"]
    svc.decide(pid, "reject", "analyst-1", reason="too noisy for us")
    db.events.update_many({}, {"$set": {"analyzed_at": None}})            # same session analyzed again
    svc.poll_once()
    p = db.proposals.find_one({"proposal_id": pid})
    assert p["status"] == "rejected" and len(p["seen_in_batches"]) == 2
    with pytest.raises(ValueError):
        svc.decide(pid, "approve", "analyst-2")


def test_approval_feeds_memory_and_removes_new_technique_flag(env):
    db, gate, make, _, _ = env
    svc = make()
    svc.poll_once()
    p = db.proposals.find_one({"technique": "T1082"})
    assert any("new technique" in f for f in p["escalation_flags"])
    svc.decide(p["proposal_id"], "approve", "analyst-1")
    assert db.memory.find_one()["technique"] == "T1082"
    assert "T1082" in gate.cfg.known_techniques
    assert gate.audit.verify() == (True, None)


def test_low_confidence_escalates_instead_of_acting(env):
    db, gate, make, _, _ = env
    db.events.delete_many({"untrusted_content": {"$regex": "SYSTEM NOTE"}})
    act = FakeActuator()
    make(llm=FakeLLM("unsure"), actuator=act).poll_once()
    assert act.sent == [] and db.escalations.find_one()
