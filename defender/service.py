"""Defender service: MongoDB events -> reliability gate (LLM) -> proposals, alerts, actions.

Loop:
  1. find attacker sessions with new (unanalyzed) events
  2. a session is ready when it has >= batch_size new events, its oldest new event waited
     batch_wait_s, or the attacker disconnected
  3. run_defender_batch() on the session's recent events (LLM output only goes through the gate)
  4. store strategy, alerts, escalations, proposals (for the analyst), execute allowed
     honeynet actions through the actuator, mark the events analyzed
LLM failures leave events unanalyzed so they are retried; a per-session call budget caps cost.

Run:  python -m defender.service
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from reliability import AuditLog, PolicyConfig, ReliabilityGate, run_defender_batch

log = logging.getLogger("defender")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return _now()


@dataclass
class DefenderConfig:
    batch_size: int = 10
    batch_wait_s: float = 30.0
    max_events_per_prompt: int = 60
    max_llm_calls_per_session: int = 20
    poll_s: float = 2.0
    actuator_url: str | None = None


class ActuatorClient:
    """POSTs an allowed honeynet action to the actuator service. Returns (ok, detail)."""

    def __init__(self, url: str | None, timeout: float = 5.0):
        self.url, self.timeout = url, timeout

    def execute(self, action: dict) -> tuple[bool, str]:
        if not self.url:
            return False, "no actuator configured"
        body = json.dumps({"tool": action["tool"], "params": action["params"]}).encode()
        req = urllib.request.Request(self.url.rstrip("/") + "/actions", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300, resp.read(500).decode(errors="replace")
        except Exception as e:  # network errors are recorded, never fatal
            return False, f"{type(e).__name__}: {e}"


class DefenderService:
    def __init__(self, db, gate: ReliabilityGate, call_llm: Callable[[str, str], str],
                 cfg: DefenderConfig | None = None, actuator: ActuatorClient | None = None,
                 clock: Callable[[], datetime] = _now):
        self.db, self.gate, self.call_llm = db, gate, call_llm
        self.cfg = cfg or DefenderConfig()
        self.actuator = actuator or ActuatorClient(self.cfg.actuator_url)
        self.clock = clock
        db["proposals"].create_index("proposal_id", unique=True)
        db["alerts"].create_index("alert_key", unique=True)
        db["events"].create_index([("session_id", 1), ("analyzed_at", 1)])

    # ------------------------------------------------------------------ batching
    def ready_sessions(self) -> list[str]:
        ready = []
        for sid in self.db["events"].distinct("session_id", {"analyzed_at": None}):
            new = list(self.db["events"].find({"session_id": sid, "analyzed_at": None}, {"ts": 1, "event_type": 1}))
            if not new:
                continue
            oldest = min(_parse_ts(e.get("ts", "")) for e in new)
            waited = (self.clock() - oldest).total_seconds()
            if (len(new) >= self.cfg.batch_size or waited >= self.cfg.batch_wait_s
                    or any(e.get("event_type") == "session_end" for e in new)):
                ready.append(sid)
        return ready

    def _memory_notes(self) -> str:
        notes = list(self.db["memory"].find({}, {"_id": 0, "summary": 1}).sort("approved_at", -1).limit(3))
        return "\n".join(f"- {n['summary']}" for n in notes if n.get("summary"))

    # ------------------------------------------------------------------ one session
    def process_session(self, session_id: str) -> dict:
        sessions = self.db["sessions"]
        state = sessions.find_one({"session_id": session_id}) or {"llm_calls": 0}
        new_ids = [e["event_id"] for e in self.db["events"].find({"session_id": session_id, "analyzed_at": None}, {"event_id": 1})]
        batch_id = "b-" + uuid.uuid4().hex[:10]

        if self.gate.cfg.kill_switch_on():
            return {"session_id": session_id, "skipped": "kill switch on"}
        if state["llm_calls"] >= self.cfg.max_llm_calls_per_session:
            self._escalate(session_id, batch_id, ["LLM call budget for this session is exhausted; analyst review needed"])
            self._mark(new_ids, batch_id)
            return {"session_id": session_id, "skipped": "budget exhausted"}

        events = list(self.db["events"].find({"session_id": session_id}, {"_id": 0}).sort("ts", -1)
                      .limit(self.cfg.max_events_per_prompt))[::-1]
        started = time.monotonic()
        try:
            result = run_defender_batch(self.gate, session_id, events, self.call_llm, self._memory_notes())
        except Exception as e:  # LLM/API failure: keep events unanalyzed so they are retried
            log.exception("LLM call failed for %s", session_id)
            self.db["errors"].insert_one({"session_id": session_id, "batch_id": batch_id, "at": self.clock(),
                                          "error": f"{type(e).__name__}: {e}"})
            return {"session_id": session_id, "error": str(e)}
        latency = round(time.monotonic() - started, 3)
        sessions.update_one({"session_id": session_id},
                            {"$inc": {"llm_calls": 1}, "$set": {"last_batch": batch_id, "updated_at": self.clock()}},
                            upsert=True)

        doc = result.to_dict()
        doc.update(batch_id=batch_id, analyzed_event_ids=new_ids, latency_s=latency, at=self.clock())
        self.db["strategies"].insert_one(doc)

        for a in result.alerts:
            key = f"{a['type']}:{a.get('event_id') or session_id}"
            self.db["alerts"].update_one({"alert_key": key}, {"$setOnInsert": {**a, "alert_key": key, "session_id": session_id,
                                                                                "batch_id": batch_id, "at": self.clock(),
                                                                                "status": "open"}}, upsert=True)
        if result.escalate:
            self._escalate(session_id, batch_id, result.escalation_reasons, result.escalated_actions)

        no_baseline = not self.gate.benign_events
        for p in result.pending_proposals:
            if p["type"] == "sigma_rule" and no_baseline:
                p["escalation_flags"].append("no benign log baseline: false-positive rate unknown")
            # $setOnInsert: re-proposing the same thing never overwrites an analyst's decision
            self.db["proposals"].update_one(
                {"proposal_id": p["proposal_id"]},
                {"$setOnInsert": {**p, "session_id": session_id, "batch_id": batch_id, "created_at": self.clock()},
                 "$addToSet": {"seen_in_batches": batch_id}}, upsert=True)

        for a in result.auto_actions:
            ok, detail = self.actuator.execute(a)
            self.db["actions"].insert_one({**a, "session_id": session_id, "batch_id": batch_id, "at": self.clock(),
                                           "executed": ok, "detail": detail})
            self.gate.audit.append("action_executed" if ok else "action_failed", session_id=session_id,
                                   tool=a["tool"], params=a["params"], detail=detail)

        self._mark(new_ids, batch_id)
        return {"session_id": session_id, "batch_id": batch_id, "status": result.status,
                "proposals": len(result.pending_proposals), "alerts": len(result.alerts),
                "auto_actions": len(result.auto_actions), "rejected": len(result.rejected),
                "escalate": result.escalate, "latency_s": latency}

    def _mark(self, ids, batch_id):
        if ids:
            self.db["events"].update_many({"event_id": {"$in": ids}}, {"$set": {"analyzed_at": self.clock(), "batch_id": batch_id}})

    def _escalate(self, session_id, batch_id, reasons, actions=()):
        self.db["escalations"].insert_one({"session_id": session_id, "batch_id": batch_id, "reasons": list(reasons),
                                           "pending_actions": list(actions), "status": "open", "at": self.clock()})

    def poll_once(self) -> list[dict]:
        return [self.process_session(s) for s in self.ready_sessions()]

    def run_forever(self):
        while True:
            try:
                for r in self.poll_once():
                    log.info("batch %s", r)
            except Exception:
                log.exception("poll failed")
            time.sleep(self.cfg.poll_s)

    # ------------------------------------------------------------------ analyst (used by the dashboard)
    def decide(self, proposal_id: str, decision: str, analyst: str, reason: str = "") -> dict:
        p = self.db["proposals"].find_one({"proposal_id": proposal_id})
        if p is None:
            raise KeyError(proposal_id)
        if p.get("status") != "pending_approval":
            raise ValueError(f"proposal already {p.get('status')}")
        rec = self.gate.record_analyst_decision(p["session_id"], proposal_id, decision, analyst, reason, p.get("technique"))
        status = {"approve": "approved", "reject": "rejected", "edit": "edited"}[decision]
        self.db["proposals"].update_one({"proposal_id": proposal_id}, {"$set": {
            "status": status, "decided_by": analyst, "decision_reason": reason, "decided_at": self.clock(),
            "audit_hash": rec["hash"]}})
        if decision == "approve":
            self.db["memory"].insert_one({"session_id": p["session_id"], "proposal_id": proposal_id,
                                          "technique": p.get("technique"), "approved_at": self.clock(),
                                          "summary": f"{p['type']} for {p.get('technique') or 'n/a'} approved: {p.get('rationale', '')[:200]}"})
        return self.db["proposals"].find_one({"proposal_id": proposal_id}, {"_id": 0})


# ---------------------------------------------------------------------- entry point
def load_benign(db, path: str | None) -> list[dict]:
    events = list(db["benign_events"].find({}, {"_id": 0}).limit(5000))
    if path and Path(path).exists():
        events += [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    return events


def main():
    from pymongo import MongoClient
    from reliability.loop import bedrock_call_llm

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    env = os.environ
    db = MongoClient(env.get("MONGO_URI", "mongodb://mongodb:27017/maya")).get_default_database()
    pcfg = PolicyConfig(confidence_threshold=float(env.get("CONFIDENCE_THRESHOLD", "0.6")))
    if env.get("DECOY_HOSTS"):
        pcfg.decoy_hosts = set(env["DECOY_HOSTS"].split(","))
    pcfg.known_techniques = {m["technique"].split(".")[0] for m in db["memory"].find({"technique": {"$ne": None}})}
    gate = ReliabilityGate(pcfg, AuditLog(env.get("AUDIT_PATH", "/audit/audit.jsonl")),
                           load_benign(db, env.get("BENIGN_LOG")))
    llm = bedrock_call_llm(env["BEDROCK_MODEL_ID"], env.get("AWS_REGION", "us-west-2"))
    cfg = DefenderConfig(batch_size=int(env.get("BATCH_SIZE", "10")), batch_wait_s=float(env.get("BATCH_WAIT_S", "30")),
                         max_llm_calls_per_session=int(env.get("MAX_LLM_CALLS_PER_SESSION", "20")),
                         actuator_url=env.get("ACTUATOR_URL") or None)
    log.info("defender started: %d benign events in baseline, %d known techniques",
             len(gate.benign_events), len(pcfg.known_techniques))
    DefenderService(db, gate, llm, cfg).run_forever()


if __name__ == "__main__":
    main()
