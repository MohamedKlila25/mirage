"""Grounded analyst summary: the agent's claims, each VERIFIED by code against the source events.

For every claim the agent makes, we check (not the LLM): do the cited events exist in this session,
and does the event actually contain what the claim quotes (a command, a path, a tool)? A claim that
cites nothing real is 'unsupported' and counted as a hallucination; one whose quote isn't found is
'weak'. This is the "trust but verify" the jury asks for, and it yields a hallucination rate.
"""
from __future__ import annotations

import re

from reliability.grounding import check_evidence

QUOTED = re.compile(r"`([^`]+)`|\"([^\"]{2,})\"|'([^']{2,})'|(/[\w./-]{3,})|\b(T\d{4}(?:\.\d{3})?)\b|\b(ASI\d{2})\b")


def _quotes(text: str) -> list[str]:
    out = []
    for groups in QUOTED.findall(text or ""):
        out += [g for g in groups if g]
    return out


def check_claim(claim: dict, events_by_id: dict, session_id: str) -> dict:
    text = str(claim.get("text", ""))[:300]
    conf = float(claim.get("confidence", 0.0))
    evidence = claim.get("evidence", []) or []
    valid, reasons = check_evidence(evidence, events_by_id, session_id)
    if not valid:
        return {"text": text, "confidence": 0.0, "claimed_confidence": conf, "evidence": [],
                "check": "unsupported", "reasons": reasons or ["cites no real event of this session"]}
    quotes = _quotes(text)
    if quotes:
        hay = " ".join(str(events_by_id[e].get("untrusted_content", "")) + " " + str(events_by_id[e].get("technique", ""))
                       + " " + str(events_by_id[e].get("event_type", "")) for e in valid)
        found = [q for q in quotes if q.lower() in hay.lower()]
        if not found:
            return {"text": text, "confidence": min(conf, 0.4), "claimed_confidence": conf, "evidence": valid,
                    "check": "weak", "reasons": [f"the cited events do not contain {quotes[:3]}"]}
    return {"text": text, "confidence": conf, "claimed_confidence": conf, "evidence": valid,
            "check": "verified", "reasons": []}


def build_summary(claims: list[dict], events: list[dict], session_id: str) -> dict:
    by_id = {e["event_id"]: e for e in events}
    checked = [check_claim(c, by_id, session_id) for c in (claims or [])]
    total = len(checked)
    unsupported = sum(1 for c in checked if c["check"] == "unsupported")
    weak = sum(1 for c in checked if c["check"] == "weak")
    verified = sum(1 for c in checked if c["check"] == "verified")
    return {"claims": checked, "total": total, "verified": verified, "weak": weak, "unsupported": unsupported,
            "hallucination_rate": round(unsupported / total, 3) if total else 0.0,
            "grounding_rate": round(verified / total, 3) if total else 0.0}
