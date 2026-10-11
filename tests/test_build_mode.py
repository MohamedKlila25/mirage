"""Build mode end to end with a fake LLM: design -> validate -> stored pending -> analyst approves -> rendered."""
import json

import mongomock
import pytest

from builder.agent import design_environment, design_prompt
from builder.cli import BuildService
from builder.render import RenderConfig
from test_render import spec_dict


class FakeLLM:
    def __init__(self, *answers):
        self.answers, self.prompts = list(answers), []

    def __call__(self, system, user):
        self.prompts.append((system, user))
        a = self.answers.pop(0)
        return a if isinstance(a, str) else "```json\n" + json.dumps(a) + "\n```"


def bad_design():
    d = spec_dict()
    d["decoys"][0]["breadcrumbs"][0]["content"] = "DB_PASSWORD=hunter2"     # invented a secret
    d["decoys"][0]["hostname"] = "fake-jump-host"                           # telltale name
    return d


@pytest.fixture
def svc(tmp_path):
    db = mongomock.MongoClient().maya
    cfg = RenderConfig(deception_dir=tmp_path / "deception", render_dir=tmp_path / "render")
    return lambda *answers: BuildService(db, cfg, FakeLLM(*answers), "test-model"), db, tmp_path


def test_prompt_states_the_rules_and_the_schema():
    system, user = design_prompt("a fintech startup")
    assert "{{canary:" in system and "fake-jump-01" in system and '"EnvironmentSpec"' not in user
    assert "properties" in system and "a fintech startup" in user


def test_valid_design_on_first_try():
    r = design_environment(FakeLLM(spec_dict()))
    assert r.spec is not None and r.report.ok and len(r.raw) == 1


def test_one_retry_with_the_errors():
    llm = FakeLLM(bad_design(), spec_dict())
    r = design_environment(llm)
    assert r.report.ok and len(r.raw) == 2
    retry_prompt = llm.prompts[1][1]
    assert "secret-like" in retry_prompt and "gives the honeypot away" in retry_prompt


def test_garbage_twice_is_invalid():
    r = design_environment(FakeLLM("not json", "still not json"))
    assert r.spec is None and not r.report.ok


def test_design_is_stored_pending_and_nothing_is_rendered(svc):
    make, db, tmp = svc
    doc = make(spec_dict()).design("payments company")
    assert doc["status"] == "pending" and db.environments.count_documents({}) == 1
    assert not (tmp / "deception").exists()                                  # nothing renders before approval


def test_invalid_design_cannot_be_approved(svc):
    make, db, _ = svc
    s = make(bad_design(), bad_design())
    doc = s.design()
    assert doc["status"] == "invalid" and doc["errors"]
    with pytest.raises(ValueError):
        s.approve(doc["env_id"], "analyst-1")


def test_approve_renders_and_records_who(svc):
    make, db, tmp = svc
    s = make(spec_dict())
    env_id = s.design()["env_id"]
    out = s.approve(env_id, "analyst-1")
    assert out["manifest"]["fake-db-01"] == ["/var/backups/customers.sql"]
    e = db.environments.find_one({"env_id": env_id})
    assert e["status"] == "approved" and e["active"] and e["decided_by"] == "analyst-1"
    assert (tmp / "render" / "fake-jump-01" / "fs.pickle").exists()
    with pytest.raises(ValueError):
        s.approve(env_id, "analyst-2")                                       # decided once


def test_only_one_active_environment(svc):
    make, db, _ = svc
    s = make(spec_dict(), spec_dict())
    a, b = s.design()["env_id"], s.design()["env_id"]
    s.approve(a, "analyst-1")
    s.approve(b, "analyst-1")
    assert [e["env_id"] for e in db.environments.find({"active": True})] == [b]


def test_reject_needs_a_reason(svc):
    make, db, _ = svc
    s = make(spec_dict())
    env_id = s.design()["env_id"]
    with pytest.raises(ValueError):
        s.reject(env_id, "analyst-1", " ")
    s.reject(env_id, "analyst-1", "too obviously fake")
    assert db.environments.find_one({"env_id": env_id})["status"] == "rejected"


def test_rerender_resets_agent_changes(svc):
    make, db, tmp = svc
    s = make(spec_dict())
    env_id = s.design()["env_id"]
    s.approve(env_id, "analyst-1")
    f = tmp / "deception" / "fake-jump-01" / "opt" / "payouts" / ".env"
    original = f.read_text()
    f.write_text("tailored by the agent during a run\n")
    s.rerender(env_id)
    assert f.read_text() == original                                         # same canary values, same file
