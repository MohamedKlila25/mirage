"""Build a SessionState from MongoDB, the same way for every policy."""
from __future__ import annotations

from .policies.base import SessionState


def load_session_state(db, session_id: str) -> SessionState:
    events = list(db["events"].find({"session_id": session_id}, {"_id": 0}).sort("ts", 1))
    sess = db["sessions"].find_one({"session_id": session_id}) or {}
    planted = list(db["decoys"].find({"session_id": session_id}, {"_id": 0}))
    actions = list(db["actions"].find({"session_id": session_id}, {"_id": 0}).sort("ts", 1))
    pending = [a for a in actions if a.get("status") == "pending"]
    return SessionState(session_id=session_id, events=events, tier=int(sess.get("tier", 1)),
                        planted=planted, actions=actions, pending_approvals=pending)
