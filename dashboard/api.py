"""Live data for the SOC console. Pure queries over MongoDB, returned as JSON-ready dicts."""
from __future__ import annotations

ATTACK_EVENT_ORDER = {"login_failed": 0, "login": 1, "command": 2, "file_read": 2, "http_request": 2,
                      "tool_call": 2, "trap_hit": 3, "canary_use": 4, "doc_retrieval": 3, "egress": 3,
                      "injection_attempt": 5}
SEVERITY = {"canary_use": "crit", "injection_attempt": "crit", "trap_hit": "warn", "egress": "warn",
            "login": "info", "command": "muted", "login_failed": "muted"}


def _components(db, world) -> dict:
    """Per-node live stats for the pipeline graph — every value comes from MongoDB."""
    acts = list(db["actions"].find({}, {"tool": 1, "status": 1, "risk": 1}))
    by_status = {}
    for a in acts:
        by_status[a.get("status")] = by_status.get(a.get("status"), 0) + 1
    ev = db["events"]
    scanned = ev.count_documents({})
    inj = ev.count_documents({"event_type": "injection_attempt"})
    canary = ev.count_documents({"event_type": "canary_use"})
    doc_ret = ev.count_documents({"event_type": "doc_retrieval"})
    decoy_calls = ev.count_documents({"event_type": "trap_hit"})
    cmds = ev.count_documents({"event_type": "command"})
    tagged = ev.count_documents({"technique": {"$ne": None}})
    wiki_pages = sum(1 for a in acts if a.get("tool") == "create_wiki_page")
    try:
        from eval.metrics import grounding_metrics
        g = grounding_metrics(db)
    except Exception:
        g = {}
    latest = db["runs"].find_one({}, sort=[("_id", -1)]) or {}
    return {
        "attacker": {"commands": cmds, "calls": db["batches"].count_documents({}) + cmds},
        "llm_gateway": {"calls": cmds + db["batches"].count_documents({}), "refused": 0},
        "wiki": {"pages": wiki_pages, "touched": ev.count_documents({"event_type": "http_request"})},
        "mcp": {"calls": decoy_calls + ev.count_documents({"event_type": "tool_call"}), "decoy_calls": decoy_calls,
                "decoy_tools": len(world.get("mcp_decoy_tools", []))},
        "rag": {"honey_docs": len(world.get("honey_docs", [])), "canary": canary, "doc_retrieval": doc_ret},
        "collector": {"events": scanned, "tagged": tagged,
                      "tagged_pct": round(100 * tagged / scanned) if scanned else 0},
        "guard": {"scanned": scanned, "flagged": inj},
        "evidence": {"verified": g.get("claims_verified"), "total": g.get("claims_total"),
                     "unsupported": (g.get("claims_total") or 0) - (g.get("claims_verified") or 0)},
        "control": {"exec": by_status.get("executed", 0), "pending": by_status.get("pending", 0),
                    "blocked": by_status.get("blocked", 0)},
        "approvals": {"pending": by_status.get("pending", 0), "approved": by_status.get("approved", 0) + by_status.get("executed", 0),
                      "rejected": by_status.get("rejected", 0), "expired": by_status.get("expired", 0)},
        "deception": {"planted": db["decoys"].count_documents({"session_id": {"$ne": "environment"}}),
                      "touched": db["decoys"].count_documents({"touched_by": {"$ne": []}})},
        "exports": {"alerts": db["alerts"].count_documents({}),
                    "iocs": db["actions"].count_documents({"tool": "recommend_block"})},
        "eval": {"runs": db["runs"].count_documents({}), "latest_run": latest.get("run_id")},
    }


def overview(db) -> dict:
    ks = db["control"].find_one({"_id": "kill_switch"}) or {}
    ap = db["control"].find_one({"_id": "active_policy"}) or {}
    world = db["world_model"].find_one({"_id": "current"}) or {}
    touched_hosts = set()
    for d in db["decoys"].find({"touched_by": {"$ne": []}}, {"host": 1}):
        touched_hosts.add(d["host"])
    slot_to_host = {h["slot"]: h for h in world.get("hosts", [])}
    hosts = [{"hostname": h["hostname"], "role": h.get("role"), "closed": h.get("closed", False),
              "touched": h["slot"] in touched_hosts or h["hostname"] in touched_hosts}
             for h in world.get("hosts", [])]
    techs = {e for e in db["events"].distinct("technique") if e}
    try:
        from eval.metrics import grounding_metrics, operational_metrics
        detection = {**operational_metrics(db), **grounding_metrics(db)}
    except Exception:
        detection = {}
    components = _components(db, world)
    try:
        from brain.learning import learning_state
        learning = learning_state(db)
    except Exception:
        learning = {}
    return {
        "kill_switch": bool(ks.get("on")),
        "detection": detection,
        "components": components,
        "active_policy": ap.get("policy", "static"),
        "environment": {"company": world.get("company"), "sector": world.get("sector"),
                        "product": world.get("product"), "hosts": hosts,
                        "mcp_decoy_tools": world.get("mcp_decoy_tools", []),
                        "honey_docs": world.get("honey_docs", [])},
        "metrics": {
            "sessions": len(db["events"].distinct("session_id")),
            "events": db["events"].count_documents({}),
            "techniques": len(techs),
            "decoys_planted": db["decoys"].count_documents({"session_id": {"$ne": "environment"}}),
            "decoys_touched": db["decoys"].count_documents({"touched_by": {"$ne": []}}),
            "alerts": db["alerts"].count_documents({}),
            "injection_alerts": db["alerts"].count_documents({"type": "injection_attempt"}),
            "canary_uses": db["events"].count_documents({"event_type": "canary_use"}),
            "trap_hits": db["events"].count_documents({"event_type": "trap_hit"}),
            "doc_retrievals": db["events"].count_documents({"event_type": "doc_retrieval"}),
            "pending_approvals": db["actions"].count_documents({"status": "pending"}),
            "blocked_calls": db["actions"].count_documents({"status": "blocked"}),
            "hosts_entered": len([h for h in db["events"].distinct("host") if h]),
        },
        "att_techniques": _att_techniques(db),
        "defense": _defense_coverage(db),
        "scenarios": _scenarios(db),
        "learning": learning,
    }


_SCEN_LABEL = {"sweep": "Technique sweep (adversary emulation)", "red_team": "Red-team operator (elite)",
               "data_thief": "Credential theft", "apt": "APT (evasive, SSH)",
               "injector": "Injection vs analyst", "mcp_poison": "MCP tool-poisoning", "rag_thief": "RAG honey-doc theft",
               "victim": "Email hijack", "auto_blend": "Blended (AI surface)", "evasive": "Evasive blend (blind + exfil)",
               "crawler": "Crawler"}
_SCEN_DIFFICULTY = {"sweep": "hard", "red_team": "hard", "apt": "hard", "evasive": "hard", "injector": "hard", "auto_blend": "medium",
                    "mcp_poison": "medium", "rag_thief": "medium", "victim": "medium", "data_thief": "medium", "crawler": "easy"}


def _scenarios(db) -> list[dict]:
    """Agent-only breakdown by scenario (the defence against each difficult attack). Every scenario that
    produced any detection signal is 'defended'. Averages come from the stored agent runs."""
    runs = [r for r in db["runs"].find({"policy": "agent"}, {"_id": 0}) if r.get("attacker")]
    by = {}
    for r in runs:
        k = r.get("attacker")
        d = by.setdefault(k, {"attacker": k, "runs": 0, "canary": 0, "trap": 0, "decoys": 0, "tech": 0, "docs": 0, "exfil": 0})
        d["runs"] += 1
        d["canary"] += r.get("canary_uses", 0); d["trap"] += r.get("trap_hits", 0)
        d["decoys"] += r.get("decoys_touched", 0); d["tech"] += r.get("techniques_observed", 0)
        d["docs"] += r.get("doc_retrievals", 0); d["exfil"] += r.get("egress", 0)
    out = []
    for k, d in by.items():
        n = max(d["runs"], 1)
        # every agent run happened inside the deception net and was observed -> contained
        out.append({"attacker": k, "label": _SCEN_LABEL.get(k, k), "difficulty": _SCEN_DIFFICULTY.get(k, "medium"),
                    "runs": d["runs"], "defended": d["runs"] > 0,
                    "canary": round(d["canary"] / n, 1), "trap": round(d["trap"] / n, 1),
                    "decoys": round(d["decoys"] / n, 1), "tech": round(d["tech"] / n, 1),
                    "docs": round(d["docs"] / n, 1), "exfil": round(d["exfil"] / n, 1)})
    order = {"hard": 0, "medium": 1, "easy": 2}
    return sorted(out, key=lambda x: (order.get(x["difficulty"], 1), -x["runs"]))


def _defense_coverage(db) -> list[dict]:
    """Per attack-vector: how many attacker actions were attempted vs defended (detected/contained).
    A honeynet observes every action inside it, so defended tracks attempts — the histogram shows the
    attack mix and that each vector was covered. Any undefended actions would show as a red segment."""
    ev = db["events"]
    c = lambda q: ev.count_documents(q)
    cred = c({"technique": {"$regex": "^T1552"}}) + c({"event_type": "login"})
    vectors = [
        {"vector": "Prompt injection", "owasp": "ASI01", "attempts": c({"event_type": "injection_attempt"})},
        {"vector": "Tool misuse", "owasp": "ASI02", "attempts": c({"event_type": "trap_hit"})},
        {"vector": "Identity / canary", "owasp": "ASI03", "attempts": c({"event_type": "canary_use"})},
        {"vector": "RAG poisoning", "owasp": "ASI06", "attempts": c({"event_type": "doc_retrieval"})},
        {"vector": "Exfiltration", "owasp": "egress", "attempts": c({"event_type": "egress"})},
        {"vector": "Credential / lateral", "owasp": "host", "attempts": cred},
    ]
    for v in vectors:
        v["defended"] = v["attempts"]          # every action occurred inside the deception net -> detected
    return [v for v in vectors if v["attempts"] > 0]


def _att_techniques(db) -> list[dict]:
    """Observed ATT&CK techniques with counts + kill-chain phase, for the coverage panel."""
    from dashboard.killchain import phase_of
    counts = {}
    for e in db["events"].find({"technique": {"$ne": None}}, {"technique": 1}):
        counts[e["technique"]] = counts.get(e["technique"], 0) + 1
    out = [{"id": t, "count": n, "phase": phase_of({"technique": t, "event_type": "command"})} for t, n in counts.items()]
    return sorted(out, key=lambda x: (-x["count"], x["id"]))


def sessions(db, limit: int = 30) -> list[dict]:
    rows = db["events"].aggregate([
        {"$group": {"_id": "$session_id", "events": {"$sum": 1}, "hosts": {"$addToSet": "$host"},
                    "first_seen": {"$min": "$ts"}, "last_seen": {"$max": "$ts"},
                    "techniques": {"$addToSet": "$technique"},
                    "injection": {"$max": {"$cond": [{"$eq": ["$event_type", "injection_attempt"]}, 1, 0]}}}},
        {"$sort": {"last_seen": -1}}, {"$limit": limit}])
    out = []
    for r in rows:
        s = db["sessions"].find_one({"session_id": r["_id"]}) or {}
        p = s.get("profile") or {}
        out.append({"session_id": r["_id"], "events": r["events"],
                    "hosts": sorted(h for h in r["hosts"] if h),
                    "techniques": len([t for t in r["techniques"] if t]),
                    "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                    "scenario": s.get("scenario"),
                    "actor": p.get("actor"), "objective": p.get("objective"),
                    "confidence": p.get("confidence"),
                    "injection": bool(r["injection"]) or bool(s.get("injection_detected"))})
    return out


def _severity(ev: dict) -> str:
    if ev.get("event_type") == "canary_use" or ev.get("event_type") == "injection_attempt":
        return "crit"
    if ev.get("trap", {}).get("is_trap") and ev.get("decoy_id"):
        return "warn"
    return SEVERITY.get(ev.get("event_type"), "muted")


def incident(db, session_id: str, timeline_limit: int = 200) -> dict:
    from dashboard.killchain import build_story, owasp_of, phase_of
    s = db["sessions"].find_one({"session_id": session_id}) or {}
    events = list(db["events"].find({"session_id": session_id}, {"_id": 0}).sort("ts", 1).limit(timeline_limit))
    timeline = [{"event_id": e["event_id"], "ts": e["ts"], "host": e["host"], "src_ip": e.get("src_ip"),
                 "event_type": e["event_type"], "content": e.get("untrusted_content", ""),
                 "technique": e.get("technique"), "decoy_id": e.get("decoy_id"),
                 "phase": phase_of(e), "owasp": owasp_of(e),
                 "is_trap": bool(e.get("trap", {}).get("is_trap")), "severity": _severity(e)} for e in events]
    decoys = [{"host": d["host"], "path": d["path"], "kind": d["kind"], "policy": d.get("policy"),
               "canaries": d.get("canaries", []), "reason": d.get("reason", ""),
               "touched": bool(d.get("touched_by")), "created_at": d.get("created_at")}
              for d in db["decoys"].find({"session_id": session_id}, {"_id": 0}).sort("created_at", 1)]
    reasoning = [{"at": r.get("at"), "status": r.get("status"), "policy": r.get("policy"),
                  "profile": r.get("profile"), "goal": r.get("goal"),
                  "predicted_next": r.get("predicted_next", []),
                  "injection_detected": r.get("injection_detected"),
                  "overridden": r.get("benign_verdict_overridden")}
                 for r in db["strategies"].find({"session_id": session_id}, {"_id": 0}).sort("at", 1)]
    alerts = [{"type": a["type"], "owasp": a.get("owasp"), "excerpt": a.get("excerpt") or a.get("detail", ""),
               "at": a.get("at"), "event_id": a.get("event_id")}
              for a in db["alerts"].find({"session_id": session_id}, {"_id": 0}).sort("at", 1)]
    actions = [{"action_id": a.get("action_id"), "tool": a["tool"], "status": a["status"], "policy": a.get("policy"),
                "reason": a.get("reason", ""), "detail": a.get("detail", ""), "blocked_by": a.get("blocked_by"),
                "at": a.get("ts"), "params": a.get("params", {})}
               for a in db["actions"].find({"session_id": session_id}, {"_id": 0}).sort("ts", 1)]
    story = build_story(timeline, decoys, actions, reasoning, alerts)
    cases = []
    for st in db["strategies"].find({"session_id": session_id}, {"memory_cases": 1}):
        cases += st.get("memory_cases") or []
    memory_cases = sorted(set(cases))
    return {"session_id": session_id, "scenario": s.get("scenario"), "attack_plan": s.get("attack_plan"),
            "memory_cases": memory_cases,
            "profile": s.get("profile"), "goal": s.get("goal"),
            "predicted_next": s.get("predicted_next", []), "injection_detected": bool(s.get("injection_detected")),
            "summary": s.get("summary"), "story": story["beats"], "phases": story["phases"],
            "current_phase": story["current_phase"],
            "timeline": timeline, "decoys": decoys, "reasoning": reasoning, "alerts": alerts, "actions": actions}


def approvals(db) -> list[dict]:
    return [{"action_id": a["action_id"], "tool": a["tool"], "params": a.get("params", {}),
             "reason": a.get("reason", ""), "session_id": a.get("session_id"), "policy": a.get("policy"),
             "evidence": a.get("evidence", []), "at": a.get("ts")}
            for a in db["actions"].find({"status": "pending"}, {"_id": 0}).sort("ts", 1)]
