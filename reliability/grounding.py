"""Trust but verify: every claim the LLM makes is checked against the source events.

- unsupported: cites no real event of this session  -> claim dropped
- weak:        events exist but don't look like that technique -> confidence capped
- verified:    events exist and match a deterministic signature for the claim

The signatures are deliberately simple and readable. They are not the detector (the traps
are); they only check that the LLM's label is plausible for the evidence it cites.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

WEAK_CONFIDENCE_CAP = 0.4

# technique (or OWASP id) -> list of (event field, regex). Any match on a cited event = support.
SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "T1078": [("event_type", r"^login$")],                                          # Valid Accounts
    "T1110": [("event_type", r"^login_failed$")],                                   # Brute Force
    "T1552": [("untrusted_content", r"\.env\b|id_rsa|credentials|passw(or)?d|\.aws/|secret|api[_-]?key|token")],
    "T1003": [("untrusted_content", r"/etc/shadow|mimikatz|lsass|hashdump|secretsdump|sam\b")],
    "T1021": [("untrusted_content", r"(^|\s)(ssh|scp|sftp|smbclient|xfreerdp|rdesktop)\s"),
              ("event_type", r"^lateral_login$")],
    "T1046": [("untrusted_content", r"\b(nmap|masscan|zmap|nc\s+-[a-z]*z|ping\s+-c)\b")],
    "T1082": [("untrusted_content", r"\b(uname|hostnamectl|lsb_release)\b|/etc/os-release")],
    "T1033": [("untrusted_content", r"\b(whoami|id|w|who)\b")],
    "T1083": [("untrusted_content", r"\b(ls|find|tree|locate)\b")],
    "T1105": [("untrusted_content", r"\b(wget|curl\s.*-[oO]|tftp|certutil)\b")],
    "T1041": [("untrusted_content", r"curl\s.*(-d|--data|-F|--upload-file)|wget\s.*--post|\bscp\s+\S+\s+\S+@|\bnc\s+\S+\s+\d+\s*<"),
              ("event_type", r"^egress$")],
    "T1048": [("event_type", r"^egress$")],
    "T1059": [("event_type", r"^command$")],
    # OWASP Agentic: proven by which trap fired
    "ASI01": [("event_type", r"^(injection_attempt|tool_call|trap_hit)$")],
    "ASI02": [("event_type", r"^(tool_call|trap_hit)$"), ("source", r"^mcp$")],
    "ASI03": [("event_type", r"^canary_use$")],
    "ASI06": [("event_type", r"^doc_retrieval$"), ("source", r"^rag$")],
}

_COMPILED = {k: [(f, re.compile(rx, re.IGNORECASE)) for f, rx in v] for k, v in SIGNATURES.items()}


def _base(tech: str) -> str:
    return tech.split(".")[0]


def event_supports(tech: str, ev: dict) -> bool:
    sigs = _COMPILED.get(_base(tech))
    if not sigs:
        return False
    return any(rx.search(str(ev.get(fld, ""))) for fld, rx in sigs)


@dataclass
class ClaimCheck:
    kind: str                 # profile | technique | owasp | action | proposal
    ref: str                  # technique id, tool name, proposal type...
    status: str               # verified | weak | unsupported
    claimed_confidence: float
    confidence: float         # after verification
    valid_evidence: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def check_evidence(evidence: list[str], events_by_id: dict[str, dict], session_id: str) -> tuple[list[str], list[str]]:
    valid, reasons = [], []
    for eid in evidence:
        ev = events_by_id.get(eid)
        if ev is None:
            reasons.append(f"cited event {eid} does not exist")
        elif ev.get("session_id") != session_id:
            reasons.append(f"cited event {eid} belongs to another session")
        else:
            valid.append(eid)
    return valid, reasons


def check_claim(kind: str, ref: str, evidence: list[str], confidence: float,
                events_by_id: dict[str, dict], session_id: str, needs_signature: bool) -> ClaimCheck:
    valid, reasons = check_evidence(evidence, events_by_id, session_id)
    if not valid:
        return ClaimCheck(kind, ref, "unsupported", confidence, 0.0, [], reasons or ["no evidence"])
    if needs_signature:
        if _base(ref) not in _COMPILED:
            reasons.append(f"{ref} has no verification signature; treated as weak")
            return ClaimCheck(kind, ref, "weak", confidence, min(confidence, WEAK_CONFIDENCE_CAP), valid, reasons)
        supporting = [e for e in valid if event_supports(ref, events_by_id[e])]
        if not supporting:
            reasons.append(f"none of the cited events look like {ref}")
            return ClaimCheck(kind, ref, "weak", confidence, min(confidence, WEAK_CONFIDENCE_CAP), valid, reasons)
        return ClaimCheck(kind, ref, "verified", confidence, confidence, supporting, reasons)
    return ClaimCheck(kind, ref, "verified", confidence, confidence, valid, reasons)
