"""MongoDB-backed world model and recorder for the agent (so the policy never touches the db itself)."""
from __future__ import annotations

from datetime import datetime, timezone


class MongoWorldModel:
    """The approved environment the agent may know and reference (names only, never credential values)."""

    def __init__(self, db):
        self.db = db

    def get(self) -> dict:
        return self.db["world_model"].find_one({"_id": "current"}, {"_id": 0}) or {}


class MongoRecorder:
    """Stores the agent's analysis (for the dashboard) and injection alerts. Called by the policy;
    this is how the agent's observations reach the db without the policy writing there directly."""

    def __init__(self, db, clock=None):
        self.db = db
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        db["alerts"].create_index("alert_key", unique=True)

    def analysis(self, session_id: str, data: dict) -> None:
        self.db["strategies"].insert_one({**data, "session_id": session_id, "at": self.clock()})
        if data.get("profile"):
            upd = {"profile": data["profile"], "predicted_next": data.get("predicted_next", []),
                   "goal": data.get("goal"), "injection_detected": data.get("injection_detected", False),
                   "updated_at": self.clock()}
            if data.get("summary"):
                upd["summary"] = data["summary"]        # grounded analyst summary (claims + hallucination rate)
            self.db["sessions"].update_one({"session_id": session_id}, {"$set": upd}, upsert=True)

    def alert(self, session_id: str, data: dict) -> None:
        key = f"{data.get('type')}:{data.get('event_id') or data.get('detail') or session_id}"
        self.db["alerts"].update_one({"alert_key": key},
                                     {"$setOnInsert": {**data, "alert_key": key, "session_id": session_id,
                                                       "status": "open", "at": self.clock()}}, upsert=True)
