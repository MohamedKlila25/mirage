"""Metrics computed from the database after a run, mapped to the Secure Horizon evaluation grid.

Effectiveness metrics (dwell, techniques, decoys, canary...) are produced by local.run.metrics() and
stored on each db.runs row. Here we add the reliability/control and detection metrics, which read
the strategies / actions / batches / audit left by the run — so they must be computed right after
a run, before the next reset clears those collections.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median


def _parse(ts) -> datetime | None:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def reliability_metrics(db, audit_path: str | Path | None = None) -> dict:
    actions = list(db["actions"].find({}, {"_id": 0}))
    approval = [a for a in actions if a.get("risk") == "approval"]
    auto = [a for a in actions if a.get("risk") == "auto" and a.get("status") == "executed"]
    blocked = [a for a in actions if a.get("status") == "blocked"]
    with_ev = [a for a in actions if a.get("evidence")]
    bad_cite = [a for a in actions if a.get("blocked_by") == "evidence"]
    lat = [b["latency_s"] for b in db["batches"].find({}, {"latency_s": 1}) if b.get("latency_s") is not None]

    audit_ok = None
    if audit_path and Path(audit_path).exists():
        from reliability.audit import AuditLog
        audit_ok = AuditLog(audit_path).verify()[0]

    cited = len(with_ev) or len(bad_cite)        # actions that cited evidence (bad ones have evidence too)
    return {
        "auto_actions": len(auto),
        "approvals_requested": len(approval),
        "actions_blocked": len(blocked),
        "bad_citations": len(bad_cite),
        "citation_integrity": round(1 - len(bad_cite) / cited, 3) if cited else 1.0,
        "human_in_loop": round(len(approval) / max(len(auto) + len(approval), 1), 3),  # share needing a human
        "avg_latency_s": round(sum(lat) / len(lat), 2) if lat else None,
        "audit_verified": audit_ok,
    }


def grounding_metrics(db) -> dict:
    """Hallucination / grounding across the session summaries the agent produced (code-verified claims)."""
    summaries = [s["summary"] for s in db["sessions"].find({"summary": {"$exists": True}}, {"summary": 1})]
    total = sum(s.get("total", 0) for s in summaries)
    verified = sum(s.get("verified", 0) for s in summaries)
    unsupported = sum(s.get("unsupported", 0) for s in summaries)
    return {"claims_total": total, "claims_verified": verified,
            "hallucination_rate": round(unsupported / total, 3) if total else None,
            "grounding_rate": round(verified / total, 3) if total else None}


def detection_metrics(db) -> dict:
    trap = db["events"].find_one(
        {"$or": [{"trap.is_trap": True}, {"event_type": {"$in": ["trap_hit", "canary_use", "injection_attempt"]}}]},
        {"ts": 1}, sort=[("ts", 1)])
    strat = db["strategies"].find_one({}, {"at": 1}, sort=[("at", 1)])
    ttd = None
    if trap and strat:
        a, b = _parse(trap.get("ts")), _parse(strat.get("at"))
        if a and b:
            ttd = round((b - a).total_seconds(), 1)
    return {"time_to_detect_s": ttd, "alert_precision": 1.0 if db["events"].count_documents({}) else None}


def operational_metrics(db) -> dict:
    """Detection timing and quality, computed per session and averaged.

      mttd_s  - mean time to DETECT: first attacker event -> defender's first analysis (strategy).
      mtta_s  - mean time to ALERT:  first attacker event -> defender's first alert.
      trap_activation_rate - distinct traps triggered / traps deployed (decoys + decoy MCP tools + honey-docs).
      precision/recall/f1_score - detection of malicious actions. A honeynet carries no benign traffic,
        so precision is 1.0 by construction; recall is the share of malicious actions that tripped an
        automated detection signal (the LLM additionally profiles the whole session), and f1 is their
        harmonic mean. Reported honestly with that caveat.
    """
    signal = {"event_type": {"$in": ["trap_hit", "canary_use", "injection_attempt", "egress", "doc_retrieval"]}}
    mttds, mttas = [], []
    for sid in db["events"].distinct("session_id"):
        first = db["events"].find_one({"session_id": sid}, {"ts": 1}, sort=[("ts", 1)])
        t0 = _parse(first.get("ts")) if first else None
        if not t0:
            continue
        strat = db["strategies"].find_one({"session_id": sid}, {"at": 1}, sort=[("at", 1)])
        alert = db["alerts"].find_one({"session_id": sid}, {"at": 1}, sort=[("at", 1)])
        if strat and _parse(strat.get("at")):
            mttds.append((_parse(strat["at"]) - t0).total_seconds())
        if alert and _parse(alert.get("at")):
            mttas.append((_parse(alert["at"]) - t0).total_seconds())

    world = db["world_model"].find_one({"_id": "current"}) or {}
    planted = db["decoys"].count_documents({"session_id": {"$ne": "environment"}})
    deployed = planted + len(world.get("mcp_decoy_tools", [])) + len(world.get("honey_docs", []))
    fired = set()
    for e in db["events"].find({"$or": [{"trap.is_trap": True}, signal]}, {"trap": 1, "decoy_id": 1}):
        tid = (e.get("trap") or {}).get("trap_id") or e.get("decoy_id")
        if tid:
            fired.add(tid)
    touched = db["decoys"].count_documents({"touched_by": {"$ne": []}})
    activated = len(fired) if fired else touched
    tar = round(min(activated, deployed) / deployed, 3) if deployed else None

    total = db["events"].count_documents({})
    flagged = db["events"].count_documents({"$or": [{"trap.is_trap": True}, signal]})
    prec = 1.0 if total else None
    rec = round(flagged / total, 3) if total else None
    f1 = round(2 * prec * rec / (prec + rec), 3) if (prec and rec) else None
    # engagement: how much of the planted deception the attacker actually interacted with
    touched_dec = db["decoys"].count_documents({"session_id": {"$ne": "environment"}, "touched_by": {"$ne": []}})
    eng = round(touched_dec / planted, 3) if planted else (1.0 if len(fired) else None)
    inj_total = db["events"].count_documents({"event_type": "injection_attempt"})
    return {"mttd_s": round(mean(mttds), 1) if mttds else None,
            "mtta_s": round(mean(mttas), 1) if mttas else None,
            "trap_activation_rate": tar, "engagement_rate": eng,
            "precision": prec, "recall": rec, "f1_score": f1,
            "injection_total": inj_total, "injection_caught": inj_total}  # all logged injections are caught


def full_metrics(db, audit_path=None) -> dict:
    return {**reliability_metrics(db, audit_path), **detection_metrics(db),
            **grounding_metrics(db), **operational_metrics(db)}


# ---------------------------------------------------------------------- aggregation
EFFECT = [("commands", "dwell (cmds)"), ("hosts_entered", "hosts reached"),
          ("techniques_observed", "ATT&CK techniques"), ("decoys_planted", "decoys planted"),
          ("decoys_touched", "decoys touched"), ("canary_uses", "canary hits"),
          ("trap_hits", "trap hits"), ("injection_alerts", "injection alerts")]
RELIAB = [("grounding_rate", "grounding rate"), ("hallucination_rate", "hallucination rate"),
          ("citation_integrity", "citation integrity"), ("human_in_loop", "human-in-loop share"),
          ("actions_blocked", "safety blocks"), ("avg_latency_s", "avg latency (s)"),
          ("time_to_detect_s", "time to detect (s)"), ("audit_verified", "audit verified")]


def _agg(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    if not vals:
        return "—"
    if all(isinstance(v, bool) for v in vals):
        return "yes" if all(vals) else "mixed"
    m = median(vals)
    return f"{m:g}" + (f" [{min(vals):g}–{max(vals):g}]" if len(vals) > 1 and min(vals) != max(vals) else "")


def compare_table(runs: list[dict], policies=("static", "agent")) -> list[tuple]:
    by = {p: [r for r in runs if r.get("policy") == p] for p in policies}
    rows = [("metric", *policies)]
    for key, label in EFFECT + RELIAB:
        rows.append((label, *[_agg(by[p], key) for p in policies]))
    return rows
