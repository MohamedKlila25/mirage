"""The no-Docker emulated decoy shell: serves the rendered environment and writes Cowrie-format logs
that the real collector ingests unchanged."""
import json
from pathlib import Path

import mongomock
import pytest

from attackers.crawler import CrawlConfig, Crawler
from builder.render import RenderConfig, render_environment
from builder.spec import EnvironmentSpec
from canary.registry import CanaryRegistry
from collector.collector import Collector, Enricher, MongoSink
from honeynet.emulated_shell import EmulatedHoneynet
from test_render import spec_dict


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


def test_login_and_commands_write_cowrie_format_logs(lab):
    db, net, reg, pw, tmp = lab
    s = net.connect("pay-jump-01", 2222, "deploy", pw)
    assert s is not None
    assert s.run("whoami").strip() == "deploy"
    assert "DB_HOST=pay-db-02" in s.run("cat /opt/payouts/.env")
    s.close()
    lines = [json.loads(l) for l in (tmp / "decoys" / "fake-jump-01" / "log" / "cowrie" / "cowrie.json").read_text().splitlines()]
    ids = [l["eventid"] for l in lines]
    assert ids[:2] == ["cowrie.session.connect", "cowrie.login.success"]
    assert "cowrie.command.input" in ids and ids[-1] == "cowrie.session.closed"
    assert all(l["src_ip"] == "10.100.0.9" and l["sensor"] == "vm" for l in lines)


def test_wrong_password_logs_failure_and_denies(lab):
    db, net, reg, pw, tmp = lab
    assert net.connect("pay-jump-01", 2222, "deploy", "nope") is None
    ids = [json.loads(l)["eventid"] for l in
           (tmp / "decoys" / "fake-jump-01" / "log" / "cowrie" / "cowrie.json").read_text().splitlines()]
    assert ids == ["cowrie.session.connect", "cowrie.login.failed"]


def test_full_local_flow_crawler_to_mongo(lab):
    """No Docker: crawler -> emulated decoys -> Cowrie logs -> collector -> Mongo, every step recorded."""
    db, net, reg, pw, tmp = lab
    cfg = CrawlConfig("pay-jump-01", "deploy", pw, decoy_hosts=("pay-jump-01", "pay-db-02", "pay-files-01"))
    res = Crawler(cfg, net).run()
    assert "pay-db-02" in res.entered_hosts                       # followed the planted .env with the canary password

    Collector(tmp / "decoys", MongoSink(db), None, Enricher(db)).poll_once()
    events = list(db.events.find({}, {"_id": 0}))
    sids = {e["session_id"] for e in events}
    assert sids == {"att-10-100-0-9"}                             # one attacker session across both decoys
    hosts = {e["host"] for e in events}
    assert {"fake-jump-01", "fake-db-01"} <= hosts
    cmds = [e["untrusted_content"] for e in events if e["event_type"] == "command"]
    assert "whoami" in cmds and any(".env" in c for c in cmds)
    techniques = {e["technique"] for e in events if e.get("technique")}
    assert "T1552.001" in techniques and "T1033" in techniques    # credential-in-file and user discovery observed
    # the found canary password was used on the db host -> a canary_use event, value masked
    assert db.events.count_documents({"event_type": "canary_use"}) >= 1
    assert reg.resolve("password_1") not in json.dumps(events)    # the real value never reached the store


def test_reload_picks_up_a_planted_file(lab):
    db, net, reg, pw, tmp = lab
    s = net.connect("pay-jump-01", 2222, "deploy", pw)
    assert "No such file" in s.run("cat /opt/payouts/secret_plan.txt")
    (tmp / "deception" / "fake-jump-01" / "opt" / "payouts" / "secret_plan.txt").write_text("merger with Acme Q4\n")
    net.reload_files()
    s2 = net.connect("pay-jump-01", 2222, "deploy", pw)
    assert "merger with Acme" in s2.run("cat /opt/payouts/secret_plan.txt")
