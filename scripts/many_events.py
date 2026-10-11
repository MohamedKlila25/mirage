"""Accumulate ~N real events in the live Event Store by running the attack on many different seeds.

Each seed is a distinct attacker (unique source IP -> its own session); events flow through the real
collector into db.events and accumulate (no reset between seeds). Fast, no Bedrock (the deception traps
and ATT&CK mapping are deterministic). So the dashboard's Event Store shows ~N events across N sessions.

Usage:  PYTHONPATH=. python scripts/many_events.py [target_events]   (default 1000)
"""
import sys

from attackers.sweep import Sweep, SweepConfig
from collector.collector import Collector, Enricher, MongoSink
from local.run import DATA, _honeynet, _reset_attack, context, metrics

target = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
ctx = context()
_reset_attack(ctx)                       # start from a clean store (keeps the environment + learning history)
coll = Collector(DATA / "decoys", MongoSink(ctx.db), DATA / "collector-state.json", Enricher(ctx.db), trap_root=DATA / "trap-logs")
net, entry, user, pw, hosts = _honeynet(ctx)

seed = 0
print(f"running attacks on different seeds until the Event Store has >= {target} events...")
while ctx.db["events"].count_documents({}) < target and seed < 400:
    seed += 1
    net.src_ip = f"10.80.{(seed // 254) % 254}.{seed % 254}"     # unique source IP -> a distinct session per seed
    res = Sweep(SweepConfig(entry, user, pw, 2222), net, run_id=f"r-sweep-{seed}").run()
    coll.poll_once()
    sid = "att-" + net.src_ip.replace(".", "-")
    ctx.db["sessions"].update_one({"session_id": sid}, {"$set": {"scenario": "sweep",
                                  "profile": {"actor": "adversary-emulation", "objective": "ATT&CK sweep"}}}, upsert=True)
    if seed % 5 == 0:
        print(f"  {seed} seeds -> {ctx.db['events'].count_documents({})} events")

ev = ctx.db["events"].count_documents({})
ss = len(ctx.db["events"].distinct("session_id"))
print(f"done: {ev} events across {ss} sessions ({seed} seeds)")
