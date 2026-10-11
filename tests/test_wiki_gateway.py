"""Phase 1 services on attack-net: the fake wiki (a trap) and the llm-gateway (the only way out)."""
import io
import json

import mongomock
import pytest
from fastapi.testclient import TestClient

from collector.collector import Collector, Enricher, MongoSink
from honeynet.gateway.app import create_app as gateway_app
from honeynet.wiki.app import create_app as wiki_app

ATTACKER = "testclient"          # TestClient's client host; session id "att-testclient"


@pytest.fixture
def wiki(tmp_path):
    w = tmp_path / "wiki"
    (w / "internal").mkdir(parents=True)
    (w / "database-migration-runbook.md").write_text("# Database migration runbook\nssh payouts@pay-db-02\n")
    (w / "internal" / "on-call-secrets.md").write_text("# On-call secrets\ntoken [canary]\n")
    (tmp_path / "control").mkdir()
    client = TestClient(wiki_app(w, tmp_path / "control", tmp_path / "trap-logs" / "wiki.jsonl", "Northwind wiki"))
    return client, tmp_path


def log_lines(tmp_path, name="wiki.jsonl"):
    return [json.loads(l) for l in (tmp_path / "trap-logs" / name).read_text().splitlines()]


def test_wiki_serves_pages_and_logs_every_request(wiki):
    client, tmp = wiki
    r = client.get("/")
    assert r.status_code == 200 and "database-migration-runbook" in r.text and "internal" not in r.text
    assert "ssh payouts@pay-db-02" in client.get("/database-migration-runbook").text
    assert client.get("/nope").status_code == 404
    logs = log_lines(tmp)
    assert [l["untrusted_content"].split(" status=")[0] for l in logs] == [
        "GET /", "GET /database-migration-runbook", "GET /nope"]
    assert all(l["event_type"] == "http_request" and l["source"] == "wiki" for l in logs)


def test_internal_pages_need_tier_2(wiki):
    client, tmp = wiki
    assert client.get("/internal/on-call-secrets").status_code == 403
    (tmp / "control" / "tiers.json").write_text(json.dumps({f"att-{ATTACKER}": 2}))
    assert client.get("/internal/on-call-secrets").status_code == 200
    assert "internal/on-call-secrets" in client.get("/").text


def test_wiki_has_no_framework_fingerprints(wiki):
    client, _ = wiki
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(path).status_code == 404
    assert client.get("/../../etc/passwd").status_code == 404


def test_collector_ingests_wiki_requests_and_marks_decoys_touched(wiki):
    client, tmp = wiki
    client.get("/database-migration-runbook")
    db = mongomock.MongoClient().maya
    db.decoys.insert_one({"decoy_id": "dec-w1", "session_id": "environment", "host": "wiki",
                          "path": "/database-migration-runbook", "touched_by": []})
    c = Collector(tmp / "decoys", MongoSink(db), None, Enricher(db), trap_root=tmp / "trap-logs")
    assert c.poll_once() == 1
    ev = db.events.find_one({}, {"_id": 0})
    assert ev["source"] == "wiki" and ev["event_type"] == "http_request" and ev["session_id"] == f"att-{ATTACKER}"
    assert ev["decoy_id"] == "dec-w1" and db.decoys.find_one()["touched_by"] == [ev["event_id"]]
    assert c.poll_once() == 0


class FakeBedrock:
    def __init__(self):
        self.requests = []

    def converse(self, **req):
        self.requests.append(req)
        return {"output": {"message": {"role": "assistant", "content": [{"text": "OK"}]}},
                "stopReason": "end_turn", "usage": {"inputTokens": 12, "outputTokens": 1}}

    def invoke_model(self, modelId, body):
        return {"body": io.BytesIO(json.dumps({"embedding": [0.1, 0.2]}).encode())}


@pytest.fixture
def gw(tmp_path):
    fake = FakeBedrock()
    app = gateway_app(fake, {"eu.anthropic.claude-haiku"}, "amazon.titan-embed-text-v2:0", 1500, 3,
                      tmp_path / "trap-logs" / "gateway.jsonl")
    return TestClient(app), fake, tmp_path


MSG = [{"role": "user", "content": [{"text": "summarize my inbox"}]}]


def test_gateway_forwards_allowed_models_and_caps_tokens(gw):
    client, fake, tmp = gw
    r = client.post("/converse", json={"caller": "victim", "model": "eu.anthropic.claude-haiku", "messages": MSG,
                                       "system": "you are an assistant", "max_tokens": 99999})
    assert r.status_code == 200 and r.json()["message"]["content"][0]["text"] == "OK"
    assert fake.requests[0]["inferenceConfig"]["maxTokens"] == 1500
    line = log_lines(tmp, "gateway.jsonl")[0]
    assert line["caller"] == "victim" and line["input_tokens"] == 12 and "summarize" not in json.dumps(line)


def test_gateway_refuses_other_models_unknown_callers_and_over_cap(gw):
    client, fake, _ = gw
    assert client.post("/converse", json={"caller": "victim", "model": "some.big-model", "messages": MSG}).status_code == 403
    assert client.post("/converse", json={"model": "eu.anthropic.claude-haiku", "messages": MSG}).status_code == 400
    codes = [client.post("/converse", json={"caller": "attacker", "model": "eu.anthropic.claude-haiku",
                                            "messages": MSG}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert len(fake.requests) == 3


def test_gateway_embeddings(gw):
    client, _, _ = gw
    r = client.post("/embed", json={"caller": "rag", "texts": ["a", "b"]})
    assert r.json() == {"embeddings": [[0.1, 0.2], [0.1, 0.2]]}


def test_gateway_lines_are_not_attack_events(gw, tmp_path):
    client, _, tmp = gw
    client.post("/converse", json={"caller": "victim", "model": "eu.anthropic.claude-haiku", "messages": MSG})
    db = mongomock.MongoClient().maya
    assert Collector(tmp / "decoys", MongoSink(db), trap_root=tmp / "trap-logs").poll_once() == 0
