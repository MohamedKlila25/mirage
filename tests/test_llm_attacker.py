"""LLM red-team agent: drives the decoys from model-chosen actions; produces events + ground truth."""
import json
from pathlib import Path

import mongomock
import pytest

from attackers.llm.agent import AttackConfig, LLMAttacker
from attackers.llm.personas import PERSONAS
from builder.render import RenderConfig, render_environment
from builder.spec import EnvironmentSpec
from canary.registry import CanaryRegistry
from collector.collector import Collector, Enricher, MongoSink
from honeynet.emulated_shell import EmulatedHoneynet
from test_render import spec_dict


class ScriptLLM:
    def __init__(self, *steps):
        self.steps, self.calls = list(steps), 0

    def __call__(self, system, user):
        self.calls += 1
        return json.dumps(self.steps.pop(0)) if self.steps else json.dumps({"action": "done", "intent": "stop"})


@pytest.fixture
def lab(tmp_path):
    db = mongomock.MongoClient().maya
    reg = CanaryRegistry(db)
    cfg = RenderConfig(deception_dir=tmp_path / "deception", render_dir=tmp_path / "render")
    render_environment(EnvironmentSpec.model_validate(spec_dict()), reg, cfg, "env-1", db)
    world = json.loads((cfg.render_dir / "world_model.json").read_text())
    net = EmulatedHoneynet(cfg.deception_dir, cfg.render_dir, world, tmp_path / "decoys")
    entry_pw = net.decoys["pay-jump-01"].logins["deploy"]
    return db, net, reg, entry_pw, tmp_path


def conf(entry_pw, persona="data_thief", **kw):
    return AttackConfig(persona, "pay-jump-01", "deploy", entry_pw,
                        decoy_hosts=("pay-jump-01", "pay-db-02", "pay-files-01"), **kw)


def test_personas_exist():
    assert set(PERSONAS) == {"data_thief", "injector", "apt", "red_team"}


def test_agent_explores_pivots_and_reads_the_db(lab):
    db, net, reg, pw, tmp = lab
    dbpw = reg.resolve("password_1")
    llm = ScriptLLM(
        {"action": "run", "host": "pay-jump-01", "command": "cat /opt/payouts/.env", "intent": "look for creds"},
        {"action": "login", "host": "pay-db-02", "user": "payouts", "password": dbpw, "intent": "pivot to db"},
        {"action": "run", "host": "pay-db-02", "command": "cat /var/backups/customers.sql", "intent": "grab the dump"},
        {"action": "done", "intent": "done"},
    )
    res = LLMAttacker(conf(pw), net, llm, run_id="r-007").run()
    assert res.entered_hosts == ["pay-jump-01", "pay-db-02"] and res.commands == 2
    assert res.stopped == "agent finished"
    assert ("pay-db-02", "payouts", dbpw) in net.connections


def test_events_flow_to_mongo(lab):
    db, net, reg, pw, tmp = lab
    llm = ScriptLLM(
        {"action": "run", "command": "whoami", "intent": "who am i"},
        {"action": "run", "command": "cat /opt/payouts/.env", "intent": "creds"},
        {"action": "done"},
    )
    LLMAttacker(conf(pw), net, llm).run()
    Collector(tmp / "decoys", MongoSink(db), None, Enricher(db)).poll_once()
    cmds = [e["untrusted_content"] for e in db.events.find({"event_type": "command"})]
    assert "whoami" in cmds and any(".env" in c for c in cmds)
    assert db.events.find_one({"event_type": "login"})["session_id"] == "att-10-100-0-9"


def test_login_with_wrong_password_fails_and_agent_continues(lab):
    db, net, reg, pw, tmp = lab
    llm = ScriptLLM(
        {"action": "login", "host": "pay-db-02", "user": "payouts", "password": "guess", "intent": "try"},
        {"action": "run", "host": "pay-db-02", "command": "ls", "intent": "look"},
        {"action": "run", "host": "pay-jump-01", "command": "whoami", "intent": "back home"},
        {"action": "done"},
    )
    res = LLMAttacker(conf(pw), net, llm).run()
    assert "pay-db-02" not in res.entered_hosts
    assert any(s.result == "no session on pay-db-02; login first" for s in res.steps)
    assert any(s.command == "whoami" for s in res.steps)


def test_out_of_scope_host_refused(lab):
    db, net, reg, pw, tmp = lab
    llm = ScriptLLM({"action": "login", "host": "corp-ad-01", "user": "a", "password": "b", "intent": "escape"},
                    {"action": "done"})
    res = LLMAttacker(AttackConfig("data_thief", "pay-jump-01", "deploy", pw,
                                   decoy_hosts=("pay-jump-01", "pay-db-02")), net, llm).run()
    assert "corp-ad-01" not in res.entered_hosts and ("corp-ad-01" not in [h for h, _, _ in net.connections])


def test_budget_caps_steps(lab):
    db, net, reg, pw, tmp = lab
    many = [{"action": "run", "command": "ls", "intent": "loop"}] * 50
    res = LLMAttacker(conf(pw, max_steps=5), net, ScriptLLM(*many)).run()
    assert len(res.steps) <= 5 and res.stopped == "step budget reached"


def test_bad_json_twice_stops(lab):
    db, net, reg, pw, tmp = lab
    class Bad:
        def __call__(self, s, u): return "I will now hack the mainframe."
    res = LLMAttacker(conf(pw), net, Bad()).run()
    assert res.stopped == "no parsable action" and res.commands == 0


def test_ssh_command_is_intercepted_as_a_pivot(lab):
    db, net, reg, pw, tmp = lab
    dbpw = reg.resolve("password_1")
    # the LLM reads the .env (sees the db password), then types a plain `ssh` command to pivot
    llm = ScriptLLM(
        {"action": "run", "command": "cat /opt/payouts/.env", "intent": "find db creds"},
        {"action": "run", "command": "ssh payouts@pay-db-02", "intent": "pivot using found password"},
        {"action": "run", "host": "pay-db-02", "command": "cat /var/backups/customers.sql", "intent": "read dump"},
        {"action": "done"},
    )
    res = LLMAttacker(conf(pw), net, llm).run()
    assert "pay-db-02" in res.entered_hosts                       # pivot worked from a typed ssh command
    assert ("pay-db-02", "payouts", dbpw) in net.connections       # it tried the password it had read
    assert any("customers.sql" in s.command for s in res.steps if s.host == "pay-db-02")


def test_sshpass_inline_password_pivot(lab):
    db, net, reg, pw, tmp = lab
    dbpw = reg.resolve("password_1")
    llm = ScriptLLM({"action": "run", "command": f"sshpass -p '{dbpw}' ssh payouts@pay-db-02", "intent": "pivot"},
                    {"action": "done"})
    res = LLMAttacker(conf(pw), net, llm).run()
    assert "pay-db-02" in res.entered_hosts


def test_groundtruth_schema(lab):
    db, net, reg, pw, tmp = lab
    llm = ScriptLLM({"action": "run", "command": "whoami", "intent": "recon"}, {"action": "done"})
    res = LLMAttacker(conf(pw, persona="injector"), net, llm).run()
    gt = res.to_groundtruth()
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "groundtruth.json").read_text())
    from jsonschema import Draft202012Validator
    assert list(Draft202012Validator(schema).iter_errors(gt)) == []
    assert gt["persona"] == "injector" and gt["steps"][0]["intent"] == "recon"
