"""Phase 0: the dashboard skeleton shows live sessions and events, read-only."""
import json
from pathlib import Path

import mongomock
import pytest

from collector.collector import normalize
from dashboard.data import counts, recent_events, sessions_overview

ROOT = Path(__file__).resolve().parents[1]
RAW = [json.loads(l) for l in (Path(__file__).parent / "fixtures" / "cowrie_real_session.json").read_text().splitlines()]
EVENTS = [e for e in (normalize(r, "fake-jump-01") for r in RAW) if e]


@pytest.fixture
def client():
    c = mongomock.MongoClient("mongodb://mongodb:27017/maya")
    return c


def test_queries_on_empty_database(client):
    db = client.get_default_database()
    assert counts(db) == {"events": 0, "sessions": 0, "pending_approvals": 0, "kill_switch": False}
    assert sessions_overview(db) == [] and recent_events(db) == []


def test_queries_on_real_cowrie_session(client):
    db = client.get_default_database()
    db.events.insert_many([dict(e) for e in EVENTS])
    db.actions.insert_one({"action_id": "act-1", "status": "pending"})
    db.control.insert_one({"_id": "kill_switch", "on": True})
    c = counts(db)
    assert c == {"events": len(EVENTS), "sessions": 1, "pending_approvals": 1, "kill_switch": True}
    [s] = sessions_overview(db)
    assert s["session_id"] == "att-127-0-0-1" and s["events"] == len(EVENTS) and s["hosts"] == "fake-jump-01"
    latest = recent_events(db, limit=3)
    assert len(latest) == 3 and "_id" not in latest[0]
    assert latest[0]["ts"] >= latest[-1]["ts"]


@pytest.mark.parametrize("with_events", [False, True])
def test_app_renders(client, monkeypatch, with_events):
    testing = pytest.importorskip("streamlit.testing.v1")
    import pymongo
    import streamlit as st

    if with_events:
        client.get_default_database().events.insert_many([dict(e) for e in EVENTS])
    monkeypatch.setattr(pymongo, "MongoClient", lambda *a, **k: client)
    st.cache_resource.clear()
    at = testing.AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=30).run()
    assert not at.exception
    assert at.title[0].value.startswith("Mirage")
    assert at.metric[0].value == ("1" if with_events else "0")
    if with_events:
        assert len(at.dataframe) == 2
    else:
        assert "No attacker activity yet." in [i.value for i in at.info]
