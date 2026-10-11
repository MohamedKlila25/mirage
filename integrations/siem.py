"""SIEM integration: Mirage is SIEM-agnostic. It emits alerts as ECS-style JSON lines any SIEM can
ingest, and exports each observed detection as a ready-to-paste Splunk (SPL) and Elastic (ES|QL)
query. This is the "technical integration" story: no lock-in, plugs in front of Splunk/Elastic/SOAR.
"""
from __future__ import annotations

import json
from pathlib import Path

SEVERITY = {"canary_use": 90, "injection_attempt": 85, "trap_hit": 80, "egress": 75, "doc_retrieval": 60,
            "login": 40, "command": 30, "login_failed": 20}
OWASP = {"injection_attempt": "ASI01", "trap_hit": "ASI02", "canary_use": "ASI03", "doc_retrieval": "ASI06"}

# how a real SIEM would detect each technique on normal host telemetry (field patterns)
QUERY_HINTS = {
    "T1552.001": ("credential access in files", r"\.env|credential|passwd|id_rsa|\.aws"),
    "T1087.001": ("local account discovery", r"/etc/passwd|getent passwd"),
    "T1021.004": ("ssh lateral movement", r"\bssh\b"),
    "T1005": ("data from local system", r"mysqldump|pg_dump|cp .*\.(sql|db)"),
    "T1033": ("owner/user discovery", r"\bwhoami\b|\bid\b"),
    "T1082": ("system information discovery", r"\buname\b|/etc/os-release"),
    "T1105": ("ingress tool transfer", r"\bwget\b|\bcurl\b"),
    "T1083": ("file and directory discovery", r"\bfind\b|\bls\b"),
}


def to_ecs(ev: dict) -> dict:
    """One Mirage event -> an ECS-style alert record (dotted keys; any SIEM reads this)."""
    et = ev.get("event_type", "")
    rec = {
        "@timestamp": ev.get("ts"),
        "event.kind": "alert" if ev.get("trap", {}).get("is_trap") or et in OWASP else "event",
        "event.category": ["intrusion_detection"],
        "event.action": et,
        "event.dataset": "mirage.honeynet",
        "event.severity": SEVERITY.get(et, 25),
        "event.provider": "mirage",
        "message": ev.get("untrusted_content", ""),
        "source.ip": ev.get("src_ip"),
        "host.name": ev.get("host"),
        "user.name": ev.get("user"),
        "labels.session": ev.get("session_id"),
        "labels.mirage_decoy": bool(ev.get("trap", {}).get("is_trap")),
        "labels.trap_id": ev.get("trap", {}).get("trap_id"),
        "labels.agent_id": ev.get("agent_id"),
    }
    if ev.get("technique"):
        rec["threat.technique.id"] = ev["technique"]
        rec["threat.framework"] = "MITRE ATT&CK"
    if et in OWASP:
        rec["threat.tactic.name"] = "OWASP-Agentic"
        rec["labels.owasp"] = OWASP[et]
    return {k: v for k, v in rec.items() if v is not None}


def export_alerts(db, out_path: str | Path) -> int:
    """Write every malicious/trap event as an ECS JSON line. Returns the count."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    q = {"$or": [{"trap.is_trap": True},
                 {"event_type": {"$in": ["trap_hit", "canary_use", "injection_attempt", "egress",
                                         "doc_retrieval", "login", "command"]}}]}
    n = 0
    with out_path.open("w", encoding="utf-8") as f:
        for ev in db["events"].find(q, {"_id": 0}).sort("ts", 1):
            f.write(json.dumps(to_ecs(ev)) + "\n")
            n += 1
    return n


def siem_queries(db) -> str:
    """Per observed technique and approved IOC: a Splunk SPL and an Elastic ES|QL query."""
    techs = sorted(t for t in db["events"].distinct("technique") if t)
    iocs = [a["params"]["ioc"] for a in db["actions"].find({"tool": "recommend_block", "status": "approved"})
            if a.get("params", {}).get("ioc")]
    lines = ["# Mirage → SIEM detections", "", "Paste into your SIEM. Fields map to ECS (`event.action`, "
             "`threat.technique.id`, `source.ip`).", ""]
    lines.append("## Techniques observed\n")
    for t in techs:
        label, pat = QUERY_HINTS.get(t, (t, ""))
        spl = f'index=edr event.action=command | regex message="{pat}"' if pat else f'index=edr "threat.technique.id"={t}'
        esql = (f'FROM logs-* | WHERE event.action=="command" AND message RLIKE "(?i).*({pat}).*"' if pat
                else f'FROM logs-* | WHERE "threat.technique.id"=="{t}"')
        lines += [f"### {t} — {label}", "**Splunk**", "```spl", spl, "```", "**Elastic (ES|QL)**", "```esql", esql, "```", ""]
    if iocs:
        lines.append("## Blocked IOCs\n")
        joined = ",".join(f'"{i}"' for i in iocs)
        lines += ["**Splunk**", "```spl", f"index=* (src.ip IN ({joined}) OR url.domain IN ({joined}))", "```",
                  "**Elastic (ES|QL)**", "```esql", f"FROM logs-* | WHERE source.ip IN ({joined})", "```", ""]
    return "\n".join(lines)


def export_all(db, out_dir: str | Path) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    n = export_alerts(db, out_dir / "alerts.jsonl")
    (out_dir / "siem_queries.md").write_text(siem_queries(db), encoding="utf-8")
    return {"alerts": n, "alerts_file": str(out_dir / "alerts.jsonl"), "queries_file": str(out_dir / "siem_queries.md")}
