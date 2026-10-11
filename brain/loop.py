"""The brain loop: run the active policy on each attacker session, through mirage-control only.

  - the active policy is Static or Agent; it is forced to Static whenever the kill switch is on
  - every action the policy returns goes through MirageControl (same checks as the MCP server),
    so the brain never writes decoys, control flags or action records itself
  - batching mirrors the pre-v4 defender service: a session is handled when it has enough new
    events, has waited long enough, or the attacker disconnected

Static mode is the baseline and the kill-switch fallback (the environment is already rendered,
so Static only observes / escalates tiers on a schedule). Agent mode adapts (brain/policies/agent.py).
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .policies.base import Policy
from .session import load_session_state

log = logging.getLogger("brain")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return _now()


@dataclass
class BrainConfig:
    batch_size: int = 10
    batch_wait_s: float = 30.0
    poll_s: float = 2.0
    max_llm_calls_per_session: int = 20


class BrainLoop:
    def __init__(self, db, control, policies: dict[str, Policy], cfg: BrainConfig | None = None,
                 clock: Callable[[], datetime] = _now):
        self.db, self.control, self.policies = db, control, policies
        self.cfg = cfg or BrainConfig()
        self.clock = clock
        db["events"].create_index([("session_id", 1), ("brain_at", 1)])

    # ------------------------------------------------------------------ active policy
    def active_policy_name(self) -> str:
        if self.control.kill_switch_on():
            return "static"
        doc = self.db["control"].find_one({"_id": "active_policy"})
        name = (doc or {}).get("policy", "static")
        return name if name in self.policies else "static"

    def set_policy(self, name: str, by: str) -> None:
        if name not in self.policies:
            raise ValueError(f"unknown policy {name}")
        self.db["control"].update_one({"_id": "active_policy"},
                                      {"$set": {"policy": name, "by": by, "at": self.clock()}}, upsert=True)
        self.control.audit.append("active_policy", policy=name, by=by)

    # ------------------------------------------------------------------ batching
    def ready_sessions(self) -> list[str]:
        ready = []
        for sid in self.db["events"].distinct("session_id", {"brain_at": None}):
            new = list(self.db["events"].find({"session_id": sid, "brain_at": None}, {"ts": 1, "event_type": 1}))
            if not new:
                continue
            waited = (self.clock() - min(_parse_ts(e.get("ts", "")) for e in new)).total_seconds()
            if (len(new) >= self.cfg.batch_size or waited >= self.cfg.batch_wait_s
                    or any(e.get("event_type") == "session_end" for e in new)):
                ready.append(sid)
        return ready

    # ------------------------------------------------------------------ one session
    def process_session(self, session_id: str) -> dict:
        name = self.active_policy_name()
        policy = self.policies[name]
        state = load_session_state(self.db, session_id)
        new_events = list(self.db["events"].find({"session_id": session_id, "brain_at": None}, {"_id": 0}).sort("ts", 1))
        if not new_events:
            return {"session_id": session_id, "skipped": "no new events"}
        batch_id = "b-" + uuid.uuid4().hex[:10]

        sess = self.db["sessions"].find_one({"session_id": session_id}) or {}
        if policy.uses_llm and sess.get("llm_calls", 0) >= self.cfg.max_llm_calls_per_session:
            self._record(session_id, batch_id, name, [], skipped="llm budget exhausted")
            self._mark(new_events, batch_id)
            return {"session_id": session_id, "skipped": "llm budget exhausted"}

        started = time.monotonic()
        try:
            actions = policy.decide(state, new_events)
        except Exception as e:  # LLM/policy failure: leave events for retry
            log.exception("policy %s failed on %s", name, session_id)
            self.db["errors"].insert_one({"session_id": session_id, "batch_id": batch_id, "policy": name,
                                          "at": self.clock(), "error": f"{type(e).__name__}: {e}"})
            return {"session_id": session_id, "error": str(e)}
        if policy.uses_llm:
            self.db["sessions"].update_one({"session_id": session_id}, {"$inc": {"llm_calls": 1}}, upsert=True)

        results = []
        for a in actions[:policy.max_actions]:
            r = self.control.call(a.tool, a.params, a.reason, a.evidence, name, session_id, batch_id)
            results.append({"tool": a.tool, **r})

        self._record(session_id, batch_id, name, results, latency_s=round(time.monotonic() - started, 3))
        self._mark(new_events, batch_id)
        return {"session_id": session_id, "batch_id": batch_id, "policy": name, "actions": len(results),
                "executed": sum(r["status"] == "executed" for r in results),
                "pending": sum(r["status"] == "pending" for r in results),
                "blocked": sum(r["status"] == "blocked" for r in results)}

    def _record(self, session_id, batch_id, policy, results, **extra):
        self.db["batches"].insert_one({"batch_id": batch_id, "session_id": session_id, "policy": policy,
                                       "actions": results, "at": self.clock(), **extra})

    def _mark(self, events, batch_id):
        ids = [e["event_id"] for e in events]
        if ids:
            self.db["events"].update_many({"event_id": {"$in": ids}},
                                          {"$set": {"brain_at": self.clock(), "brain_batch": batch_id}})

    # ------------------------------------------------------------------ run
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
