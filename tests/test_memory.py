"""Defender-side incident memory: distinct cases, similarity retrieval, the prompt block, and the
anti-poisoning safety rule (no raw attacker text stored)."""
import mongomock

from brain.memory import Memory


def _seed(db, sid, techniques, objective, touched_path=None):
    db.events.insert_many([{"session_id": sid, "event_type": "command", "technique": t} for t in techniques])
    db.sessions.insert_one({"session_id": sid, "scenario": "x",
                            "profile": {"actor": "ai_agent", "objective": objective, "skill": "high", "confidence": 0.9},
                            "summary": {"claims": [{"text": "claimed X", "check": "unsupported"}]}})
    db.decoys.insert_one({"session_id": sid, "kind": "credentials", "host": "h", "path": "/opt/.env",
                          "touched_by": ["e"] if touched_path else []})
    db.actions.insert_one({"session_id": sid, "tool": "recommend_block", "status": "rejected", "reason": "IOC is ours", "ts": "t"})


def test_record_creates_distinct_cases_even_with_same_session_id():
    db = mongomock.MongoClient().maya
    m = Memory(db)
    _seed(db, "att-1", ["T1552.001", "T1083"], "exfiltrate data", touched_path=True)
    m.record_incident("att-1")
    db.events.delete_many({}); db.sessions.delete_many({}); db.decoys.delete_many({})
    _seed(db, "att-1", ["T1552.001", "T1021.004"], "exfiltrate data")   # same session_id, new incident
    m.record_incident("att-1")
    assert db.incident_memory.count_documents({}) == 2                   # not overwritten


def test_retrieve_similar_ranks_by_technique_overlap():
    db = mongomock.MongoClient().maya
    m = Memory(db)
    for sid, techs, obj in [("att-1", ["T1552.001", "T1083", "T1078"], "exfiltrate"),
                            ("att-2", ["T1046", "T1595"], "recon")]:
        _seed(db, sid, techs, obj); m.record_incident(sid)
        db.events.delete_many({}); db.sessions.delete_many({}); db.decoys.delete_many({})
    hits = m.retrieve_similar(["T1552.001", "T1083"], "exfiltrate", 2)
    assert hits and hits[0]["session_id"] == "att-1" and "T1552.001" in hits[0]["techniques"]   # best overlap first


def test_prompt_block_has_cases_scores_rejections_and_no_raw_attacker_text():
    db = mongomock.MongoClient().maya
    m = Memory(db)
    _seed(db, "att-1", ["T1552.001", "T1083"], "exfiltrate data", touched_path=True)
    m.record_incident("att-1")
    block, used = m.prompt_block(["T1552.001"], "exfiltrate")
    assert used and "DEFENDER MEMORY" in block
    assert "decoys that WORKED" in block or "Lures that work" in block
    assert "IOC is ours" in block                                        # analyst rejection fed back
    # safety: the record stores only defender-side facts, never raw untrusted_content
    rec = db.incident_memory.find_one({})
    assert "untrusted_content" not in rec and set(rec).issubset(
        {"_id", "case_id", "session_id", "reviewed", "scenario", "profile", "techniques", "decoys",
         "actions", "injections", "halluc_examples", "decoys_planted", "decoys_touched"})


def test_disabled_memory_returns_empty_block():
    db = mongomock.MongoClient().maya
    m = Memory(db, enabled=False)
    _seed(db, "att-1", ["T1083"], "recon"); m.record_incident("att-1")
    assert m.prompt_block(["T1083"], "recon") == ("", [])
