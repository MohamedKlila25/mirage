"""Kill-chain phases + a time-ordered attacker<->Mirage 'story' for the Attack Story dashboard.

Every observed event maps to one of six honeynet kill-chain phases, and every defender response
(profile, decoy, alert, action) becomes a story beat on Mirage's side. The console renders the beats
as two paired columns under a phase rail that lights up as the attacker advances. Pure functions over
plain dicts so the API and tests can call them without a database."""
from __future__ import annotations

# ordered kill-chain phases (honeynet narrative, left -> right)
PHASES = ["recon", "access", "discovery", "collection", "exfil", "contained"]
PHASE_LABEL = {"recon": "Recon", "access": "Access", "discovery": "Discovery",
               "collection": "Collection", "exfil": "Exfil", "contained": "Contained"}

# ATT&CK technique (base id, sub-technique stripped) -> phase
_TECH_PHASE = {
    "T1595": "recon", "T1046": "recon", "T1018": "recon", "T1082": "recon", "T1016": "recon",
    "T1033": "recon", "T1049": "recon", "T1057": "recon",
    "T1078": "access", "T1110": "access", "T1021": "access", "T1133": "access",
    "T1552": "discovery", "T1083": "discovery", "T1087": "discovery", "T1069": "discovery",
    "T1005": "collection", "T1560": "collection", "T1105": "collection", "T1213": "collection",
    "T1119": "collection", "T1530": "collection", "T1114": "collection", "T1070": "collection",
    "T1053": "collection",
    "T1567": "exfil", "T1041": "exfil", "T1048": "exfil", "T1020": "exfil",
}
# event_type -> phase (takes priority over technique for these honeynet-specific signals)
_EVENT_PHASE = {
    "injection_attempt": "access", "login": "access", "login_failed": "access", "session_start": "access",
    "canary_use": "exfil", "egress": "exfil",
    "doc_retrieval": "collection", "tool_call": "collection", "trap_hit": "collection",
    "file_read": "collection", "http_request": "recon",
}
# terminal containment tools -> the Contained phase
CONTAIN_TOOLS = {"recommend_block", "revoke_agent_token", "disable_mcp_tool", "close_host", "quarantine"}

_OWASP = {"injection_attempt": "ASI01", "trap_hit": "ASI02", "canary_use": "ASI03",
          "doc_retrieval": "ASI06", "egress": "ASI02"}


def phase_of(ev: dict) -> str:
    """Kill-chain phase for one observed event."""
    et = ev.get("event_type")
    if _EVENT_PHASE.get(et):
        return _EVENT_PHASE[et]
    base = str(ev.get("technique") or "").split(".")[0]
    return _TECH_PHASE.get(base, "discovery")


def owasp_of(ev: dict) -> str | None:
    """OWASP Agentic category for an event, if it is an agentic-threat signal."""
    tid = str((ev.get("trap") or {}).get("trap_id") or ev.get("decoy_id") or "")
    if "tool_poisoning" in tid or tid.startswith("rag:"):
        return "ASI06"
    if tid.startswith("mcp:"):
        return "ASI02"
    return _OWASP.get(ev.get("event_type"))


def phase_index(phase: str) -> int:
    return PHASES.index(phase) if phase in PHASES else 0


# attacker event_type -> (short label, severity hint). detail carries the raw content.
_ATK = {
    "login": ("logged in", "info"), "login_failed": ("failed login", "muted"),
    "session_start": ("opened session", "muted"), "command": ("ran command", "muted"),
    "file_read": ("read file", "info"), "http_request": ("web request", "muted"),
    "doc_retrieval": ("retrieved honey-doc", "warn"), "tool_call": ("called tool", "info"),
    "trap_hit": ("took the bait", "warn"), "canary_use": ("used canary secret", "crit"),
    "egress": ("tried to exfiltrate", "crit"), "injection_attempt": ("attempted prompt injection", "crit"),
}


def _beat(ts, side, phase, kind, title, detail="", technique=None, owasp=None, severity="muted", host=""):
    return {"ts": ts, "side": side, "phase": phase, "kind": kind, "title": title,
            "detail": (detail or "")[:200], "technique": technique, "owasp": owasp,
            "severity": severity, "host": host or ("mirage" if side == "mirage" else "")}


def build_story(timeline: list[dict], decoys: list[dict], actions: list[dict],
                reasoning: list[dict], alerts: list[dict]) -> dict:
    """Merge attacker events and Mirage's responses into one time-ordered list of beats, and report
    which kill-chain phases have been reached. The console splits beats by `side` into two columns."""
    beats: list[dict] = []
    reached = set()

    for e in timeline:
        ph = e.get("phase") or phase_of(e)
        reached.add(ph)
        label, sev_hint = _ATK.get(e.get("event_type"), ("event", "muted"))
        sev = e.get("severity") or sev_hint
        if e.get("is_trap") and sev == "muted":
            sev = "warn"
        beats.append(_beat(e.get("ts"), "attacker", ph, e.get("event_type", "event"),
                           label, e.get("content", ""), e.get("technique"),
                           e.get("owasp") or owasp_of(e), sev, host=e.get("host", "")))

    # Mirage: the first useful profile read
    for r in reasoning:
        p = r.get("profile") or {}
        if p.get("actor"):
            conf = p.get("confidence")
            c = f" ({round(conf * 100)}%)" if isinstance(conf, (int, float)) else ""
            beats.append(_beat(r.get("at"), "mirage", "access", "profile",
                               f"profiled: {p.get('actor')}{c}", p.get("objective", ""), severity="info"))
            break

    for d in decoys:
        beats.append(_beat(d.get("created_at"), "mirage", "collection", "decoy",
                           f"planted decoy · {d.get('host','')}:{d.get('path','')}",
                           d.get("reason", ""), severity="info", host=d.get("host", "")))

    for a in alerts:
        beats.append(_beat(a.get("at"), "mirage", "exfil", "alert",
                           f"alert · {a.get('type','')}", a.get("excerpt", ""),
                           owasp=a.get("owasp"), severity="crit"))

    for a in actions:
        tool = a.get("tool", "")
        ph = "contained" if tool in CONTAIN_TOOLS else "collection"
        if ph == "contained":
            reached.add("contained")
        st = a.get("status", "")
        beats.append(_beat(a.get("at"), "mirage", ph, "action",
                           f"{tool} · {st}", a.get("reason", ""),
                           severity="warn" if st in ("pending", "blocked") else "info"))

    beats.sort(key=lambda b: (str(b["ts"] or ""), 0 if b["side"] == "attacker" else 1))

    high = max((phase_index(p) for p in reached), default=-1)
    phases = [{"key": p, "label": PHASE_LABEL[p], "reached": i <= high, "current": i == high}
              for i, p in enumerate(PHASES)]
    return {"beats": beats, "phases": phases,
            "current_phase": PHASES[high] if high >= 0 else None}
