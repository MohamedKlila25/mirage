"""AgentPolicy: the adaptive brain. Reads the batch, profiles the attacker, and returns actions
that plant decoys tailored to what they just did. The heart of the project.

It only decides; the brain loop sends every action through mirage-control, which re-checks it.
A recorder (injected by the brain) stores the agent's analysis and injection alerts, so the
policy itself never writes to MongoDB (hard rule 4). Injection is detected deterministically
(regex + optional fast classifier) before and independently of the LLM, and a benign verdict on
a session with injection attempts is overridden — the agent cannot talk itself out of an alert.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Protocol

from pydantic import ValidationError

from brain.agent.prompt import build_agent_prompt
from brain.agent.schema import AgentOutput
from brain.agent.summary import build_summary
from reliability.untrusted import scan_for_injection, scan_text

from .base import Action, Policy, SessionState

BENIGN_WORDS = {"benign", "none", "legitimate", "authorized", "false_positive", "admin_activity", "safe", "harmless"}
LLM = Callable[[str, str], str]


class Recorder(Protocol):
    def analysis(self, session_id: str, data: dict) -> None: ...
    def alert(self, session_id: str, data: dict) -> None: ...


class WorldModel(Protocol):
    def get(self) -> dict: ...


def _strip_fences(raw: str) -> str:
    m = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    return (m.group(1) if m else raw).strip()


class AgentPolicy(Policy):
    name = "agent"
    uses_llm = True
    max_actions = 3

    def __init__(self, call_llm: LLM, world: WorldModel, recorder: Recorder | None = None,
                 classify: Callable[[str], bool] | None = None, memory=None):
        self.call_llm = call_llm
        self.world = world
        self.recorder = recorder
        self.classify = classify            # optional cheap LLM classifier; regex is the floor
        self.memory = memory                # defender-side incident memory (case-based learning)

    # ------------------------------------------------------------------ injection (deterministic)
    def _injection(self, session_id: str, new_events: list[dict]) -> str:
        findings = scan_for_injection(new_events)
        extra = []
        if self.classify:
            for ev in new_events:
                if ev["event_id"] not in {f.event_id for f in findings} and self.classify(str(ev.get("untrusted_content", ""))):
                    extra.append(ev["event_id"])
        if not findings and not extra:
            return ""
        if self.recorder:
            for f in findings:
                self.recorder.alert(session_id, {"type": "injection_attempt", "owasp": "ASI01",
                                                 "event_id": f.event_id, "patterns": list(f.patterns), "excerpt": f.excerpt})
            for eid in extra:
                self.recorder.alert(session_id, {"type": "injection_attempt", "owasp": "ASI01",
                                                 "event_id": eid, "patterns": ["classifier"], "excerpt": ""})
        n = len(findings) + len(extra)
        return f"{n} prompt-injection attempt(s) detected in this batch."

    # ------------------------------------------------------------------ decide
    def decide(self, state: SessionState, new_events: list[dict]) -> list[Action]:
        world = self.world.get()
        injection_note = self._injection(state.session_id, new_events)
        memory_block, cases_used = "", []
        if self.memory is not None:
            try:
                techs = {e.get("technique") for e in state.events} | {e.get("technique") for e in new_events}
                obj = ""
                for e in reversed(new_events + list(state.events)):
                    if e.get("event_type") in ("trap_hit", "doc_retrieval", "egress"):
                        obj = e.get("event_type"); break
                memory_block, cases_used = self.memory.prompt_block(sorted(t for t in techs if t), obj)
            except Exception:
                memory_block, cases_used = "", []
        system, user = build_agent_prompt(state, new_events, world, injection_note, memory_block)

        out = self._call(system, user)
        if out is None:
            hint = "\n\nYour previous answer was not valid JSON for the schema. Answer again with only valid JSON."
            out = self._call(system, user + hint)
        if out is None:
            if self.recorder:
                self.recorder.analysis(state.session_id, {"policy": "agent", "status": "invalid_output",
                                                           "injection_detected": bool(injection_note)})
            last = new_events[-1]["event_id"]
            return [Action("observe", {"session_id": state.session_id, "note": "agent output invalid; observing"},
                           "LLM output could not be parsed twice", [last], "agent")]

        overridden = bool(injection_note) and out.profile.objective.lower() in BENIGN_WORDS
        if self.recorder:
            # grounded summary: verify every claim the agent makes against the session's events (code, not LLM)
            pool = {e["event_id"]: e for e in state.events}
            pool.update({e["event_id"]: e for e in new_events})
            summary = build_summary([c.model_dump() for c in out.summary], list(pool.values()), state.session_id)
            self.recorder.analysis(state.session_id, {
                "policy": "agent", "status": "ok",
                "profile": out.profile.model_dump(),
                "predicted_next": [p.model_dump() for p in out.predicted_next],
                "goal": out.goal, "injection_detected": bool(injection_note),
                "benign_verdict_overridden": overridden, "summary": summary,
                "memory_cases": cases_used})
            if overridden:
                self.recorder.alert(state.session_id, {"type": "defender_manipulation_suspected", "owasp": "ASI01",
                                                       "detail": f"LLM called the session '{out.profile.objective}' "
                                                       "despite injection attempts in it"})

        return [Action(a.tool, dict(a.params), a.reason, list(a.evidence), "agent") for a in out.actions]

    def _call(self, system: str, user: str) -> AgentOutput | None:
        try:
            return AgentOutput.model_validate(json.loads(_strip_fences(self.call_llm(system, user))))
        except (json.JSONDecodeError, ValidationError):
            return None
