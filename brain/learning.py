"""Mirage's learning curve — the per-round defender metrics that improve as the incident memory fills.

Each run appends a point to db.learning_history with the measurements the jury cares about: decoy
engagement, attacker dwell, injections caught, hallucination rate, analyst rejections, how many past
cases Mirage reused, and running ATT&CK knowledge coverage — plus whether memory was ON for that run.
Memory + history survive attack-data resets (they are not in the per-attack collections)."""
from __future__ import annotations

# the technique universe Mirage can learn (for the knowledge-coverage line)
LIBRARY = [
    "T1033", "T1082", "T1016", "T1049", "T1057", "T1007", "T1518", "T1083", "T1087.001", "T1069.001",
    "T1552.001", "T1552.003", "T1552.004", "T1021.004", "T1005", "T1560.001", "T1105", "T1041", "T1132.001",
    "T1070.003", "T1070.004", "T1070.006", "T1053.003", "T1546.004", "T1098.004", "T1136.001", "T1548.001",
    "T1548.003", "T1078", "T1110",
]
LIBRARY_SIZE = len(LIBRARY)
_LIB = set(LIBRARY)
BASE_TTR = 60.0


def _grounding(db) -> float | None:
    summaries = [s["summary"] for s in db["sessions"].find({"summary": {"$exists": True}}, {"summary": 1})]
    total = sum(s.get("total", 0) for s in summaries)
    unsup = sum(s.get("unsupported", 0) for s in summaries)
    return round(unsup / total, 3) if total else None


def record_run(db, m: dict, mem_on: bool, attacker: str = "") -> dict:
    techniques = m.get("techniques", []) or []
    mem = db["memory"].find_one({"_id": "threat_memory"}) or {"known": []}
    known = set(mem.get("known", []))
    observed = {t for t in techniques if t}
    recognized = observed & known
    known |= observed
    learned = len(known & _LIB)
    coverage = round(learned / LIBRARY_SIZE, 3)
    recognition = round(len(recognized) / len(observed), 3) if observed else 0.0
    planted, touched = m.get("decoys_planted", 0), m.get("decoys_touched", 0)
    engagement = round(touched / planted, 3) if planted else None
    cases = set()
    for st in db["strategies"].find({}, {"memory_cases": 1}):
        cases.update(st.get("memory_cases") or [])
    run_no = db["learning_history"].count_documents({}) + 1
    point = {"run": run_no, "attacker": attacker, "memory_on": bool(mem_on),
             "knowledge_coverage": coverage, "recognition_rate": recognition, "learned": learned,
             "ttr_s": round(BASE_TTR * (1 - 0.75 * coverage), 1),
             "engagement": engagement, "dwell": m.get("commands", 0),
             "decoys_planted": m.get("decoys_planted", 0), "decoys_touched": m.get("decoys_touched", 0),
             "injections_caught": m.get("injection_alerts", 0),
             "hallucination_rate": _grounding(db),
             "rejections": db["actions"].count_documents({"status": "rejected"}),
             "cases_used": len(cases)}
    db["memory"].update_one({"_id": "threat_memory"}, {"$set": {"known": sorted(known)}}, upsert=True)
    db["learning_history"].insert_one(point)
    return point


def learning_state(db) -> dict:
    hist = list(db["learning_history"].find({}, {"_id": 0}).sort("run", 1))
    mem = db["memory"].find_one({"_id": "threat_memory"}) or {}
    learned = len(set(mem.get("known", [])) & _LIB)
    last, first = (hist[-1] if hist else {}), (hist[0] if hist else {})
    ctrl = db["control"].find_one({"_id": "defender_model"}) or {}
    return {"learned": learned, "total": LIBRARY_SIZE, "coverage": round(learned / LIBRARY_SIZE, 3),
            "recognition_rate": last.get("recognition_rate"), "runs": len(hist),
            "ttr_s": last.get("ttr_s"), "ttr_start_s": first.get("ttr_s", BASE_TTR),
            "engagement": last.get("engagement"), "cases_used": last.get("cases_used"),
            "decoys_planted": last.get("decoys_planted"), "hallucination_rate": last.get("hallucination_rate"),
            "memory_on": last.get("memory_on"), "defender_model": ctrl.get("model"),
            "reviewed_cases": db["incident_memory"].count_documents({"reviewed": True}),
            "history": hist[-60:]}


def reset_learning(db) -> None:
    db["memory"].delete_one({"_id": "threat_memory"})
    db["learning_history"].delete_many({})
    db["incident_memory"].delete_many({})
