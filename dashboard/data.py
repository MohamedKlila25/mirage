"""Read-only MongoDB queries for the dashboard. No Streamlit here, so they can be tested."""
from __future__ import annotations


def get_db(uri: str):
    from pymongo import MongoClient  # looked up at call time (tests swap in mongomock)
    return MongoClient(uri).get_default_database()


def counts(db) -> dict:
    ks = db["control"].find_one({"_id": "kill_switch"}) or {}
    return {
        "events": db["events"].count_documents({}),
        "sessions": len(db["events"].distinct("session_id")),
        "pending_approvals": db["actions"].count_documents({"status": "pending"}),
        "kill_switch": bool(ks.get("on")),
    }


def sessions_overview(db, limit: int = 50) -> list[dict]:
    """One row per attacker session, most recent activity first."""
    rows = db["events"].aggregate([
        {"$group": {"_id": "$session_id", "events": {"$sum": 1}, "hosts": {"$addToSet": "$host"},
                    "first_seen": {"$min": "$ts"}, "last_seen": {"$max": "$ts"}}},
        {"$sort": {"last_seen": -1}},
        {"$limit": limit},
    ])
    return [{"session_id": r["_id"], "events": r["events"], "hosts": ", ".join(sorted(r["hosts"])),
             "first_seen": r["first_seen"], "last_seen": r["last_seen"]} for r in rows]


def recent_events(db, limit: int = 50) -> list[dict]:
    fields = {"_id": 0, "ts": 1, "session_id": 1, "host": 1, "event_type": 1, "untrusted_content": 1, "event_id": 1}
    return list(db["events"].find({}, fields).sort("ts", -1).limit(limit))
