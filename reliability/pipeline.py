"""The reliability gate: the only path from LLM output to any action.

    events ──> scan injection ──> prompt (untrusted data wrapped) ──> LLM
                                                                     │
    actuator <── auto ── policy ── verify claims ── validate rules ── schema
    analyst  <── pending_approval (+ evidence, validation, escalation reasons)
    audit    <── every decision, hash-chained

Nothing the LLM says is executed or shown as a recommendation unless it survives this gate.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

from pydantic import ValidationError

from .audit import AuditLog
from .grounding import ClaimCheck, check_claim, check_evidence
from .policy import PolicyConfig, check_honeynet_action, check_proposal_payload
from .schema import Strategy, json_schema_for_prompt
from .sigma_check import validate_rule
from .untrusted import SYSTEM_PROMPT_RULES, InjectionFinding, scan_for_injection, wrap_untrusted

BENIGN_WORDS = {"benign", "none", "legitimate", "authorized", "false_positive", "admin_activity"}


@dataclass
class GateResult:
    session_id: str
    status: str                                  # ok | invalid_output | killed
    session_confidence: float = 0.0
    escalate: bool = False
    escalation_reasons: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    claims: list[ClaimCheck] = field(default_factory=list)
    auto_actions: list[dict] = field(default_factory=list)       # send to the actuator
    escalated_actions: list[dict] = field(default_factory=list)  # honeynet actions needing a human
    pending_proposals: list[dict] = field(default_factory=list)  # show to the analyst
    rejected: list[dict] = field(default_factory=list)           # never shown as recommendations
    retry_hint: str | None = None                                # feed back to the LLM once

    def to_dict(self) -> dict:
        return asdict(self)


def build_prompt(events: list[dict], memory_notes: str = "", session_id: str = "") -> tuple[str, str]:
    """(system, user) messages for the LLM call."""
    system = (SYSTEM_PROMPT_RULES + "\n\nJSON schema:\n" + json.dumps(json_schema_for_prompt()))
    user = f"Session to analyze: {session_id} (use exactly this value as session_id)\n\n" if session_id else ""
    if memory_notes:
        user += f"Similar approved past incidents (trusted, from our own memory):\n{memory_notes}\n\n"
    user += "Evidence for this session:\n" + wrap_untrusted(events)
    return system, user


def _strip_fences(raw: str) -> str:
    m = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    return (m.group(1) if m else raw).strip()


def _pid(ptype: str, payload: dict) -> str:
    return "p-" + hashlib.sha256((ptype + json.dumps(payload, sort_keys=True)).encode()).hexdigest()[:10]


class ReliabilityGate:
    def __init__(self, cfg: PolicyConfig, audit: AuditLog, benign_events: list[dict]):
        self.cfg = cfg
        self.audit = audit
        self.benign_events = benign_events

    # ------------------------------------------------------------------ main entry
    def process(self, session_id: str, events: list[dict], raw_llm_output: str) -> GateResult:
        out_hash = hashlib.sha256(raw_llm_output.encode()).hexdigest()
        event_ids = [e["event_id"] for e in events]

        if self.cfg.kill_switch_on():
            r = GateResult(session_id, "killed", escalate=True, escalation_reasons=["kill switch is on"])
            self.audit.append("gate_killed", session_id=session_id, llm_output_sha256=out_hash)
            return r

        # 1. schema
        try:
            strat = Strategy.model_validate(json.loads(_strip_fences(raw_llm_output)))
            if strat.session_id != session_id:
                raise ValueError(f"session_id {strat.session_id!r} does not match {session_id!r}")
        except (json.JSONDecodeError, ValidationError, ValueError) as e:
            msg = str(e)[:1500]
            r = GateResult(session_id, "invalid_output", escalate=True,
                           escalation_reasons=["LLM output failed schema validation"],
                           retry_hint=f"Your previous answer was rejected: {msg}. Answer again with JSON that matches the schema exactly.")
            self.audit.append("gate_invalid_output", session_id=session_id, error=msg,
                              input_event_ids=event_ids, llm_output_sha256=out_hash)
            return r

        r = GateResult(session_id, "ok")
        by_id = {e["event_id"]: e for e in events}          # lookup may include other sessions
        events = [e for e in events if e.get("session_id") == session_id]

        # 2. injection (deterministic, independent of what the LLM concluded)
        findings: list[InjectionFinding] = scan_for_injection(events)
        for f in findings:
            r.alerts.append({"type": "injection_attempt", "owasp": "ASI01", "event_id": f.event_id,
                             "patterns": list(f.patterns), "excerpt": f.excerpt})

        # 3. profile
        pc = check_claim("profile", strat.profile.objective, strat.profile.evidence,
                         strat.profile.confidence, by_id, session_id, needs_signature=False)
        r.claims.append(pc)
        r.session_confidence = pc.confidence
        if pc.status == "unsupported":
            r.escalation_reasons.append("attacker profile cites no valid evidence")
        if findings and strat.profile.objective.lower() in BENIGN_WORDS:
            r.session_confidence = 0.0
            pc.status, pc.confidence = "overridden", 0.0
            pc.reasons.append("benign verdict on a session with injection attempts is not trusted")
            r.alerts.append({"type": "defender_manipulation_suspected", "owasp": "ASI01",
                             "detail": f"LLM concluded '{strat.profile.objective}' on a session containing injection attempts"})
            r.escalation_reasons.append("LLM verdict may have been manipulated by injected text")
        if findings:
            r.escalation_reasons.append(f"{len(findings)} injection attempt(s) in this session")

        # 4. technique / OWASP claims
        verified_techs = set()
        for c in strat.attack_techniques:
            chk = check_claim("technique", c.id, c.evidence, c.confidence, by_id, session_id, needs_signature=True)
            r.claims.append(chk)
            if chk.status == "verified":
                verified_techs.add(c.id.split(".")[0])
        for c in strat.owasp_agentic:
            r.claims.append(check_claim("owasp", c.id, c.evidence, c.confidence, by_id, session_id, needs_signature=True))
        if strat.attack_techniques and not verified_techs:
            r.escalation_reasons.append("no technique claim could be verified against the events")

        low_conf = r.session_confidence < self.cfg.confidence_threshold
        if low_conf:
            r.escalation_reasons.append(
                f"session confidence {r.session_confidence:.2f} < threshold {self.cfg.confidence_threshold}")

        # 5. honeynet actions (auto only if allowed, grounded, and confident)
        for a in strat.honeynet_actions:
            item = {"tool": a.tool, "params": a.params, "reason": a.reason, "evidence": a.evidence}
            valid, ev_errs = check_evidence(a.evidence, by_id, session_id)
            decision, reasons = check_honeynet_action(a.tool, a.params, session_id, self.cfg)
            if not valid:
                decision, reasons = "rejected", reasons + ev_errs + ["action cites no valid evidence"]
            if decision == "auto" and (low_conf or (findings and a.tool != "kill_session")):
                decision, reasons = "escalated", ["needs a human: low confidence or manipulation attempt in session"]
            item.update(decision=decision, reasons=reasons)
            {"auto": r.auto_actions, "escalated": r.escalated_actions}.get(decision, r.rejected).append(item)

        # 6. proposals (never automatic)
        for p in strat.proposals:
            pid = _pid(p.type, p.payload)
            item = {"proposal_id": pid, "type": p.type, "payload": p.payload, "technique": p.technique,
                    "confidence": p.confidence, "evidence": p.evidence, "rationale": p.rationale,
                    "status": "pending_approval", "escalation_flags": [], "validation": None, "reasons": []}
            valid, ev_errs = check_evidence(p.evidence, by_id, session_id)
            errs = check_proposal_payload(p.type, p.payload, self.cfg) + ([] if valid else ev_errs + ["no valid evidence"])
            if p.type == "sigma_rule" and not errs:
                v = validate_rule(p.payload["yaml"], events, self.benign_events, valid)
                item["validation"] = asdict(v)
                if not v.passed:
                    errs += ["sigma validation failed: " + "; ".join(v.reasons)]
            if errs:
                item.update(status="rejected", reasons=errs)
                r.rejected.append(item)
                continue
            flags = item["escalation_flags"]
            if p.confidence < self.cfg.confidence_threshold:
                flags.append(f"low confidence {p.confidence:.2f}")
            if p.technique and p.technique.split(".")[0] not in verified_techs:
                flags.append(f"technique {p.technique} not verified against the evidence")
            if p.technique and p.technique.split(".")[0] not in self.cfg.known_techniques:
                flags.append(f"new technique {p.technique} (not in approved memory)")
            if strat.profile.actor == "ai_agent":
                flags.append("attacker is an AI agent")
            if findings:
                flags.append("session contains injection attempts")
            r.pending_proposals.append(item)

        r.escalate = bool(r.escalation_reasons or r.escalated_actions)

        # 7. audit: one record for the batch, one per decision
        self.audit.append("gate_decision", session_id=session_id, input_event_ids=event_ids,
                          llm_output_sha256=out_hash, session_confidence=r.session_confidence,
                          escalate=r.escalate, escalation_reasons=r.escalation_reasons,
                          alerts=r.alerts, claims=[asdict(c) for c in r.claims])
        for kind, items in (("action_auto", r.auto_actions), ("action_escalated", r.escalated_actions),
                            ("proposal_pending", r.pending_proposals), ("rejected", r.rejected)):
            for it in items:
                self.audit.append(kind, session_id=session_id, item=it)
        return r

    # ------------------------------------------------------------------ human decisions
    def record_analyst_decision(self, session_id: str, proposal_id: str, decision: str,
                                analyst: str, reason: str = "", technique: str | None = None) -> dict:
        if decision not in {"approve", "reject", "edit"}:
            raise ValueError("decision must be approve, reject or edit")
        if decision in {"reject", "edit"} and not reason.strip():
            raise ValueError("a reason is required to reject or edit (it feeds memory)")
        if decision == "approve" and technique:
            self.cfg.known_techniques.add(technique.split(".")[0])
        return self.audit.append("analyst_decision", session_id=session_id, proposal_id=proposal_id,
                                 decision=decision, analyst=analyst, reason=reason)
