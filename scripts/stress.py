"""Stress-test the deception layer: run N scripted attacks straight through the traps and ingest them.

The traps (canaries ASI03, decoy MCP tools ASI02, honey-docs ASI06, injection scan ASI01) fire
deterministically, so detection scales without the LLM. Each run is a REAL execution: it gets its own
session (unique source IP), its events flow through the real collector into db.events, and a summary row
goes to db.runs. So every dashboard number — Event Store, sessions, defense coverage, scenarios — reflects
the full scale. The LLM defender is intentionally not invoked here (that runs on live interactive sessions).

Usage:  PYTHONPATH=. python scripts/stress.py [N] [--no-live]   (default 1000)
By default it first runs ONE real live agent attack (so grounding / MTTD metrics stay populated), then
appends N scripted attacks' worth of events. --no-live skips the Bedrock step (grounding shows blank).
"""
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

import ai_traps.victim as V
from ai_traps.mcp_company import MCPCompany
from ai_traps.victim import DOCS, SCRIPTS
from collector.collector import Collector, Enricher, MongoSink
from local.run import DATA, context, run_attack

args = [a for a in sys.argv[1:] if not a.startswith("--")]
N = int(args[0]) if args else 1000
NO_LIVE = "--no-live" in sys.argv
SCEN = ["mcp_poison", "rag_thief", "victim", "evasive", "auto_blend"]

ctx = context(); db = ctx.db
if not NO_LIVE:                                    # one real live run to seed grounding + MTTD (also resets)
    try:
        print("seeding one live agent run (for grounding / MTTD metrics) ...", flush=True)
        run_attack(ctx, "agent", 1, 0.3, "auto")
    except Exception as e:
        print(f"  (live seed skipped: {type(e).__name__} {e})", flush=True)
db.runs.delete_many({"stress": True})              # keep the live run's data; append stress to it

sdir = DATA / "stress"; shutil.rmtree(sdir, ignore_errors=True)
trap = sdir / "trap-logs" / "mcp.jsonl"; trap.parent.mkdir(parents=True, exist_ok=True)
collector = Collector(DATA / "decoys", MongoSink(db), sdir / "collector-state.json",
                      Enricher(db), trap_root=sdir / "trap-logs")

t0 = time.time(); recs = []; detected = 0; pos = 0
for i in range(N):
    scen = SCEN[i % len(SCEN)]
    src = f"10.90.{i // 250}.{i % 250}"            # unique -> one session per attack
    sid = "att-" + src.replace(".", "-")
    mcp = MCPCompany(db, trap, docs=dict(DOCS), src_ip=src)
    mcp.scan_descriptions()
    res = V.VictimAssistant(mcp, SCRIPTS[scen]()).run()
    collector.poll_once()                          # trap-log delta -> db.events (enriched)
    with trap.open(encoding="utf-8") as f:         # count just this run's lines for the summary row
        f.seek(pos); new = f.readlines(); pos = f.tell()
    k = Counter(json.loads(l)["event_type"] for l in new)
    sig = sum(k.get(t, 0) for t in ("trap_hit", "canary_use", "doc_retrieval", "injection_attempt", "egress"))
    detected += 1 if sig > 0 else 0
    db.sessions.update_one({"session_id": sid}, {"$set": {"scenario": scen}}, upsert=True)
    recs.append({"policy": "agent", "attacker": scen, "seed": i, "stress": True, "run_id": f"stress-{scen}-{i}",
                 "canary_uses": k.get("canary_use", 0), "trap_hits": k.get("trap_hit", 0),
                 "doc_retrievals": k.get("doc_retrieval", 0), "egress": k.get("egress", 0),
                 "injection_alerts": k.get("injection_attempt", 0), "decoys_touched": 0, "decoys_planted": 0,
                 "techniques_observed": 0, "hosts_entered": 1, "commands": res.commands, "elapsed_s": 0.0})
    if (i + 1) % 200 == 0:
        print(f"  {i+1}/{N} ...", flush=True)
db.runs.insert_many(recs)
print(f"ran {N} scripted attacks in {time.time()-t0:.1f}s | detected {detected}/{N}")
print("db.events:", db.events.count_documents({}), "| sessions:", len(db.events.distinct("session_id")),
      "| agent runs:", db.runs.count_documents({"policy": "agent"}))
