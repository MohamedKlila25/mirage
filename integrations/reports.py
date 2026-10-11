"""Analyst deliverables: a per-incident report and a NIS2 24-hour early-warning draft (Markdown).

Both are drafts for a human to review — Mirage never files anything itself. They are built from the
same verified data the console shows (profile, grounded summary, timeline, decoys, recommendations).
"""
from __future__ import annotations

from datetime import datetime, timezone

from dashboard.api import incident as _incident


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def incident_report_md(db, session_id: str) -> str:
    inc = _incident(db, session_id)
    p = inc.get("profile") or {}
    L = [f"# Incident report — {session_id}", f"_Generated {_ts()} · DRAFT for analyst review_", ""]
    L += ["## Attacker profile",
          f"- **Type:** {p.get('actor', 'unknown')} · skill {p.get('skill', '—')}",
          f"- **Assessed objective:** {p.get('objective', '—')} (confidence {round((p.get('confidence') or 0) * 100)}%)",
          f"- **Goal pursued:** {inc.get('goal', '—')}",
          f"- **Prompt-injection against the defender:** {'YES — session locked' if inc.get('injection_detected') else 'no'}", ""]

    s = inc.get("summary")
    if s and s.get("claims"):
        L.append("## What happened (each claim verified against source events)")
        for c in s["claims"]:
            mark = {"verified": "✓", "weak": "~", "unsupported": "✗ (unverified)"}.get(c["check"], "·")
            L.append(f"- {mark} {c['text']}  _(evidence: {', '.join(c.get('evidence', [])) or 'none'})_")
        L.append(f"\n_Grounding: {s.get('verified', 0)}/{s.get('total', 0)} claims verified, "
                 f"hallucination rate {round((s.get('hallucination_rate') or 0) * 100)}%._\n")

    techs = sorted({e["technique"] for e in inc["timeline"] if e.get("technique")})
    if techs:
        L += ["## ATT&CK techniques observed", ", ".join(techs), ""]

    if inc["decoys"]:
        L.append("## Deception deployed")
        for d in inc["decoys"]:
            L.append(f"- `{d['host']}:{d['path']}` ({d['policy']}){' — TOUCHED' if d['touched'] else ''} — {d['reason']}")
        L.append("")

    if inc["actions"]:
        rec = [a for a in inc["actions"] if a["status"] in ("pending", "approved")]
        if rec:
            L.append("## Recommended / approved response")
            for a in rec:
                L.append(f"- **{a['tool']}** `{a.get('params', {})}` [{a['status']}] — {a.get('reason', '')}")
            L.append("")

    L += ["## Key timeline"]
    for e in inc["timeline"][:40]:
        tag = f" [{e['technique']}]" if e.get("technique") else ""
        L.append(f"- `{e['ts']}` {e['host']} · {e['event_type']}: {e['content'][:90]}{tag}")
    L += ["", "## Limitations",
          "- Only covers activity that touched a decoy or the supervised MCP layer.",
          "- Profile is an AI assessment; claims marked unverified are not evidence-backed.", ""]
    return "\n".join(L)


def nis2_draft_md(db, session_id: str) -> str:
    inc = _incident(db, session_id)
    p = inc.get("profile") or {}
    hosts = sorted({e["host"] for e in inc["timeline"]})
    techs = sorted({e["technique"] for e in inc["timeline"] if e.get("technique")})
    exfil = any(e["event_type"] == "egress" for e in inc["timeline"])
    return "\n".join([
        f"# NIS2 — 24-hour early warning (DRAFT) — {session_id}",
        f"_Generated {_ts()}. Draft only; legal/compliance must review before submission to the CSIRT._", "",
        "## 1. Entity & contact", "- Entity: <your organisation>  · Sector: <sector>  · Contact: <SOC on-call>", "",
        "## 2. Nature of the incident",
        f"- Suspected {p.get('actor', 'actor')} with assessed objective **{p.get('objective', 'unknown')}** "
        f"(confidence {round((p.get('confidence') or 0) * 100)}%).",
        f"- Detected via deception honeynet. Affected (decoy) hosts: {', '.join(hosts) or '—'}.",
        f"- Techniques (ATT&CK): {', '.join(techs) or '—'}.",
        f"- Prompt-injection against defensive AI: {'yes (OWASP ASI01)' if inc.get('injection_detected') else 'no'}.", "",
        "## 3. Suspected cross-border impact", "- None identified yet (activity contained to the deception environment).", "",
        "## 4. Suspected unlawful / malicious cause",
        f"- {'Yes' if True else 'Under assessment'} — unauthorised access and "
        f"{'attempted data exfiltration' if exfil else 'reconnaissance / credential access'} observed.", "",
        "## 5. Initial measures taken",
        "- Attacker confined to the honeynet; no production systems affected.",
        "- Recommended containment: " + (", ".join(sorted({a["tool"] for a in inc["actions"] if a["status"] in ("pending", "approved")})) or "under review") + ".", "",
        "_This is an early warning under NIS2 Art. 23; a full notification follows within 72 hours._",
    ])
