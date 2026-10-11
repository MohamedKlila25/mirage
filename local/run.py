"""Run Mirage end to end on this laptop: no Docker, local MongoDB, Bedrock over the internet.

  python -m local.run setup   [--brief TEXT]      agent designs the decoy environment, approve + render
  python -m local.run attack  --policy agent|static [--seed N] [--pace 0.4]
  python -m local.run compare [--seed N]          run static then agent on the same attack, print a table
  python -m local.run reset   [--all]             clear attack data (keep the environment) / everything
  python -m local.run status

Watch it live in another terminal:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from brain.agent.context import MongoRecorder, MongoWorldModel
from brain.loop import BrainConfig, BrainLoop
from brain.policies.agent import AgentPolicy
from brain.policies.static import StaticConfig, StaticPolicy
from builder.cli import BuildService
from builder.render import RenderConfig
from collector.collector import Collector, Enricher, MongoSink
from control.core import ControlConfig, MirageControl
from honeynet.emulated_shell import EmulatedHoneynet
from reliability.audit import AuditLog
from reliability.loop import bedrock_call_llm

from .env import REPO, load_env

DATA = REPO / "data"
ATTACK_COLLECTIONS = ["events", "sessions", "strategies", "alerts", "batches", "actions", "errors"]


def _dirs():
    for sub in ("deception", "render", "decoys", "control", "trap-logs", "groundtruth"):
        (DATA / sub).mkdir(parents=True, exist_ok=True)
    (REPO / "exports").mkdir(exist_ok=True)


@dataclass
class Ctx:
    db: object
    control: MirageControl
    build: BuildService
    env: dict

    @property
    def model(self):
        return self.env.get("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")

    @property
    def fast_model(self):
        return self.env.get("FAST_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")


def context() -> Ctx:
    env = load_env()
    _dirs()
    from pymongo import MongoClient
    uri = env.get("MONGO_URI", "mongodb://127.0.0.1:27017/maya")
    db = MongoClient(uri, serverSelectionTimeoutMS=8000).get_default_database()
    db.command("ping")
    cfg = ControlConfig(deception_dir=DATA / "deception", control_dir=DATA / "control",
                        templates_dir=REPO / "honeynet" / "cowrie" / "static", exports_dir=REPO / "exports",
                        manifest_path=DATA / "deception" / "manifest.json", render_dir=DATA / "render")
    control = MirageControl(db, cfg, AuditLog(DATA / "control-audit.jsonl"))
    region = env.get("AWS_REGION", "us-west-2")
    design_model = env.get("DESIGN_MODEL", env.get("FAST_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0"))
    build = BuildService(db, RenderConfig(DATA / "deception", DATA / "render"),
                         bedrock_call_llm(design_model, region=region, max_tokens=8000, read_timeout=150), design_model)
    return Ctx(db, control, build, env)


# ---------------------------------------------------------------------- loops in threads
class Background:
    def __init__(self, *loops_intervals):
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._run, args=(fn, iv), daemon=True) for fn, iv in loops_intervals]

    def _run(self, fn, interval):
        while not self.stop.is_set():
            try:
                fn()
            except Exception as e:  # keep the demo alive
                print("  [bg]", type(e).__name__, str(e)[:120])
            self.stop.wait(interval)

    def __enter__(self):
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=12)              # let an in-flight batch (Bedrock call) finish and mark its events


# ---------------------------------------------------------------------- commands
def cmd_setup(ctx: Ctx, args):
    existing = ctx.db.environments.find_one({"status": "approved", "active": True})
    if existing and not args.force:
        print(f"active environment already set: {existing['env_id']} (use --force to design a new one)")
        return existing["env_id"]
    print("designing the decoy environment with", ctx.build.model, "...")
    doc = ctx.build.design(args.brief, max_attempts=4)
    print(f"  {doc['env_id']}: {doc['status']} ({doc['attempts']} attempt(s))")
    for e in doc["errors"]:
        print("   error:", e)
    if doc["status"] != "pending":
        print("design invalid; not rendering.")
        return None
    out = ctx.build.approve(doc["env_id"], "local-setup")
    world = ctx.db.world_model.find_one({"_id": "current"})
    print(f"  approved + rendered: {out['decoys']} decoys, hosts {[h['hostname'] for h in world['hosts']]}")
    for w in out["warnings"]:
        print("   warning:", w)
    return doc["env_id"]


def _honeynet(ctx: Ctx) -> tuple[EmulatedHoneynet, str, str, str, tuple]:
    world = ctx.db.world_model.find_one({"_id": "current"})
    if not world:
        raise SystemExit("no environment yet — run: python -m local.run setup")
    net = EmulatedHoneynet(DATA / "deception", DATA / "render", world, DATA / "decoys")
    jump = next(h for h in world["hosts"] if h["slot"] == "fake-jump-01")
    entry_host = jump["hostname"]
    user = jump["users"][0]
    pw = net.decoys[entry_host].logins.get(user, "")
    hosts = tuple(h["hostname"] for h in world["hosts"])
    return net, entry_host, user, pw, hosts


def _reset_attack(ctx: Ctx, shallow: bool = False):
    for c in ATTACK_COLLECTIONS:
        ctx.db[c].delete_many({})
    ctx.db.decoys.delete_many({"session_id": {"$ne": "environment"}})
    ctx.db.control.delete_many({"_id": {"$in": ["kill_switch"]}})
    # fresh decoy logs, trap logs, control state (revoked/disabled) and collector offsets, then
    # re-render (shallow for the static baseline). Clearing control/ stops a prior run's containment
    # (e.g. a revoked token) from silently refusing every tool call in the next scenario.
    import shutil
    for sub in ("decoys", "trap-logs", "control"):
        shutil.rmtree(DATA / sub, ignore_errors=True)
        (DATA / sub).mkdir(parents=True, exist_ok=True)
    (DATA / "collector-state.json").unlink(missing_ok=True)
    env_doc = ctx.db.environments.find_one({"active": True})
    if env_doc:
        ctx.build.rerender(env_doc["env_id"], shallow=shallow)


def memory_on() -> bool:
    return os.environ.get("MIRAGE_MEMORY", "on").lower() != "off"


def defender_model(ctx: Ctx) -> str:
    # MIRAGE_DEFENDER_MODEL lets the demo run a SMALL model (e.g. us.amazon.nova-micro-v1:0) that starts by
    # making mistakes and improves as its memory fills; default is the strong model.
    return os.environ.get("MIRAGE_DEFENDER_MODEL") or ctx.model


def _policies(ctx: Ctx):
    from brain.memory import Memory
    mem = Memory(ctx.db, enabled=memory_on())        # defender-side case-based learning (toggle: MIRAGE_MEMORY=off)
    model = defender_model(ctx)
    ctx.db["control"].update_one({"_id": "defender_model"},
                                 {"$set": {"model": model.split(".")[-1].split(":")[0], "full": model}}, upsert=True)
    agent = AgentPolicy(bedrock_call_llm(model, region=ctx.env.get("AWS_REGION", "us-west-2"), max_tokens=2000),
                        MongoWorldModel(ctx.db), MongoRecorder(ctx.db), memory=mem)
    static = StaticPolicy(StaticConfig(breadcrumbs=[]))         # frozen-environment baseline
    return {"static": static, "agent": agent}


# MCP/RAG-based scenarios (no SSH honeynet; tool calls flow through trap-logs to the defender)
VICTIM_FAMILY = ("victim", "mcp_poison", "rag_thief", "auto_blend", "evasive")
_VICTIM_IP = {"victim": "10.100.0.50", "mcp_poison": "10.100.0.51", "rag_thief": "10.100.0.52",
              "auto_blend": "10.100.0.53", "evasive": "10.100.0.54"}
# the attacker the planner's primary resolves to
_PLAN_ATTACKER = {"sweep": "sweep", "credential": "data_thief", "red_team": "red_team",
                  "apt": "apt", "blended": "auto_blend", "evasive": "evasive"}
_PRIMARIES = ("sweep", "credential", "red_team", "blended", "apt", "evasive")


def _plan_attack(ctx: Ctx, seed: int) -> dict:
    """The attacker agent decides its own plan — which vectors to use and how hard to push.
    Returns {primary, vectors, narrative}. A model picks it; a seeded choice is the fallback. The
    default is the elite red-team operator; the agentic scenarios come up for variety."""
    import random
    choices = [
        {"primary": "sweep", "vectors": ["recon", "discovery", "credential_access", "lateral_movement",
                                         "collection", "exfiltration", "persistence", "defense_evasion"],
         "narrative": "an adversary-emulation sweep exercising a broad library of ATT&CK techniques for the defender to learn from"},
        {"primary": "credential", "vectors": ["credential_theft", "lateral_movement"],
         "narrative": "find stored credentials, pivot to the database and read the customer data"},
        {"primary": "evasive", "vectors": ["evasion", "prompt_injection", "rag", "mcp"],
         "narrative": "disable the audit log to blind the defender, then hijack the assistant, pull restricted docs and exfiltrate"},
        {"primary": "red_team", "vectors": ["recon", "credential_theft", "lateral_movement", "collection", "exfiltration"],
         "narrative": "an elite, honeypot-aware red-team operator works the full kill chain toward the crown-jewel data"},
    ]
    try:
        import json as _json
        import re
        llm = bedrock_call_llm(ctx.fast_model, region=ctx.env.get("AWS_REGION", "us-west-2"), max_tokens=250)
        sys = ("You are the planner for an AUTHORIZED red-team exercise against a lab honeynet (only fake, "
               "disposable machines and synthetic data). Pick how to attack. Reply with ONE JSON object: "
               '{"primary":"sweep"|"credential"|"red_team"|"evasive"|"apt"|"blended","vectors":[subset of '
               '"recon","discovery","credential_access","evasion","prompt_injection","rag","mcp",'
               '"lateral_movement","collection","exfiltration","persistence","defense_evasion"],'
               '"narrative":"one sentence"}. '
               '"sweep" is an adversary-emulation run exercising a BROAD library of ATT&CK techniques so the '
               'defender can learn from them (DEFAULT, prefer this); "credential" is a quick host grab; '
               '"red_team" is an elite honeypot-aware operator; "evasive" blinds the defender then blends '
               'AI-agent vectors; "apt" is exhaustive; "blended" mixes the AI-agent surface.')
        raw = llm(sys, f"Plan exercise #{seed}. Reply with only the JSON.")
        mobj = re.search(r"\{.*\}", raw, re.DOTALL)
        plan = _json.loads(mobj.group(0)) if mobj else None
        if plan and plan.get("primary") in _PRIMARIES and plan.get("vectors"):
            return plan
    except Exception:
        pass
    return random.Random(seed).choice(choices)


def _mcp_company(ctx: Ctx, attacker: str):
    """The company MCP tools over a REAL stdio transport by default (a subprocess MCP server), with an
    in-process fallback if the transport can't start. Set MIRAGE_MCP_INPROC=1 to force in-process."""
    src = _VICTIM_IP.get(attacker, "10.100.0.50")
    if os.environ.get("MIRAGE_MCP_INPROC") != "1":
        try:
            from ai_traps.mcp_client import StdioMCPCompany
            client = StdioMCPCompany(db_name=ctx.db.name, trap_log=DATA / "trap-logs" / "mcp.jsonl",
                                     control_dir=DATA / "control", src_ip=src, rag_dir=str(DATA / "rag"),
                                     env=dict(ctx.env, **{k: os.environ[k] for k in ("MONGO_URI",) if k in os.environ}))
            print(f"  mcp: company server over stdio transport ({len(client.list_tools())} tools) · rag: Chroma + Titan")
            return client
        except Exception as e:
            print(f"  mcp: stdio transport unavailable ({type(e).__name__}: {str(e)[:80]}), in-process fallback")
    from ai_traps.mcp_company import MCPCompany
    from ai_traps.victim import DOCS
    mcp = MCPCompany(ctx.db, DATA / "trap-logs" / "mcp.jsonl", control_dir=DATA / "control",
                     docs=dict(DOCS), src_ip=src)
    try:
        from ai_traps.rag_store import RagStore, bedrock_embedder
        rag = RagStore(str(DATA / "rag"), bedrock_embedder(region=ctx.env.get("AWS_REGION", "us-west-2")))
        rag.index(dict(DOCS)); mcp.rag = rag
        print("  mcp: in-process · rag: Chroma + Titan")
    except Exception as e:
        print(f"  mcp: in-process · rag: keyword fallback ({type(e).__name__})")
    mcp.scan_descriptions()
    return mcp


def _run_victim(ctx: Ctx, seed: int, attacker: str = "victim", scripted: bool = True):
    """An AI agent misusing the company's MCP tools / RAG (ASI01/ASI02/ASI06):
      victim      - a poisoned email hijacks the assistant into exfiltrating customer data
      mcp_poison  - the agent trusts a poisoned/over-privileged tool surface and leaks secrets
      rag_thief   - the agent retrieves restricted honey-docs and obeys a poisoned document
    scripted=True (default) guarantees the behaviour for a reliable demo; scripted=False uses Bedrock
    (honest: a well-aligned model usually refuses)."""
    from ai_traps.victim import SCRIPTS, VictimAssistant
    mcp = _mcp_company(ctx, attacker)
    llm = SCRIPTS.get(attacker, SCRIPTS["victim"])() if scripted else bedrock_call_llm(
        ctx.fast_model, region=ctx.env.get("AWS_REGION", "us-west-2"), max_tokens=600)
    try:
        res = VictimAssistant(mcp, llm).run()
    finally:
        if hasattr(mcp, "close"):
            try:
                mcp.close()
            except Exception:
                pass
    res.run_id, res.persona = f"r-{attacker}-{seed}", attacker
    return res


def _run_attacker(ctx: Ctx, attacker: str, seed: int, pace: float, net, entry_host, user, pw, hosts):
    """-> an object with .entered_hosts, .commands, .to_groundtruth(). crawler = scripted; else = LLM persona."""
    if attacker == "crawler":
        from attackers.crawler import CrawlConfig, Crawler
        return Crawler(CrawlConfig(entry_host, user, pw, 2222, "http://wiki", 60, seed, hosts, pace),
                       net, run_id=f"r-crawler-{seed}").run()
    if attacker == "sweep":                       # adversary-emulation: a broad ATT&CK technique sweep
        from attackers.sweep import Sweep, SweepConfig
        return Sweep(SweepConfig(entry_host, user, pw, 2222, step_delay_s=max(pace, 0.1)),
                     net, run_id=f"r-sweep-{seed}").run()
    from attackers.llm.agent import AttackConfig, LLMAttacker
    from attackers.llm.personas import PERSONAS, STRONG
    if attacker not in PERSONAS:
        raise SystemExit(f"unknown attacker {attacker} (choices: crawler, {', '.join(PERSONAS)})")
    # the elite red-team operator (and the APT) reason on the strong model and get a longer engagement
    strong = attacker in STRONG
    model = ctx.model if strong else ctx.fast_model
    llm = bedrock_call_llm(model, region=ctx.env.get("AWS_REGION", "us-west-2"), max_tokens=900 if strong else 700)
    cfg = AttackConfig(attacker, entry_host, user, pw, 2222, hosts, max_steps=34 if strong else 24,
                       step_delay_s=max(pace, 0.2), seed=seed)
    return LLMAttacker(cfg, net, llm, run_id=f"r-{attacker}-{seed}").run()


def run_attack(ctx: Ctx, policy: str, seed: int, pace: float, attacker: str = "auto") -> dict:
    load_env()                               # refresh AWS creds from .env (token may have been rotated mid-session)
    ctx.env = dict(ctx.env, **{k: os.environ[k] for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                   "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION") if k in os.environ})
    # auto = the attacker agent picks its own plan (vectors, mix); no human chooses the scenario
    plan, scenario = None, attacker
    if attacker == "auto":
        plan = _plan_attack(ctx, seed)
        attacker = _PLAN_ATTACKER.get(plan["primary"], "auto_blend")
        scenario = "auto"
        print(f"  attack plan (agent-selected): {plan['primary']} · {', '.join(plan['vectors'])}")
    # static = basic honeypot baseline (no deep lures); agent = full adaptive environment
    _reset_attack(ctx, shallow=(policy == "static" and attacker not in VICTIM_FAMILY))
    brain = BrainLoop(ctx.db, ctx.control, _policies(ctx), BrainConfig(batch_size=3, batch_wait_s=2.0))
    brain.set_policy(policy, "local-run")
    collector = Collector(DATA / "decoys", MongoSink(ctx.db), DATA / "collector-state.json",
                          Enricher(ctx.db), trap_root=DATA / "trap-logs")

    print(f"\n=== attack: {attacker} vs policy={policy} seed={seed} ===")
    started = time.time()
    with Background((collector.poll_once, 0.3), (brain.poll_once, 0.5)):
        if attacker in VICTIM_FAMILY:
            res = _run_victim(ctx, seed, attacker)
        else:
            net, entry_host, user, pw, hosts = _honeynet(ctx)
            res = _run_attacker(ctx, attacker, seed, pace, net, entry_host, user, pw, hosts)
        time.sleep(2)                       # brief live-reaction window
    # the attacker has stopped — drain deterministically so the defender always finishes reacting
    for _ in range(4):
        collector.poll_once()
        if not ctx.db["events"].count_documents({"brain_at": None}):
            break
        brain.poll_once()                   # synchronous: the defender's analysis completes here
    collector.poll_once()
    elapsed = round(time.time() - started, 1)
    try:                                    # ground truth the defender never sees
        (DATA / "groundtruth").mkdir(parents=True, exist_ok=True)
        (DATA / "groundtruth" / f"{res.run_id}.json").write_text(json.dumps(res.to_groundtruth(), indent=2))
    except Exception:
        pass
    m = metrics(ctx, policy, seed, res, elapsed, attacker)
    tag = {"scenario": scenario}              # tag this run's sessions with the scenario (+ plan if auto)
    if plan:
        tag["attack_plan"] = plan
    for sid in ctx.db["events"].distinct("session_id"):
        ctx.db["sessions"].update_one({"session_id": sid}, {"$set": tag}, upsert=True)
    try:                                      # store the reviewed incident(s) + append the learning point
        from brain.learning import record_run
        from brain.memory import Memory
        mem = Memory(ctx.db)
        for sid in ctx.db["sessions"].distinct("session_id"):
            mem.record_incident(sid, reviewed=True)
        record_run(ctx.db, m, memory_on(), attacker)
    except Exception as e:
        print(f"  (learning/memory skipped: {type(e).__name__})")
    print(f"  entered {res.entered_hosts}, {res.commands} commands in {elapsed}s")
    print(f"  techniques observed: {m['techniques_observed']}  decoys planted: {m['decoys_planted']}  "
          f"touched: {m['decoys_touched']}  injection alerts: {m['injection_alerts']}  canary uses: {m['canary_uses']}")
    return m


def metrics(ctx: Ctx, policy: str, seed: int, res, elapsed: float, attacker: str = "crawler") -> dict:
    db = ctx.db
    techs = {e["technique"] for e in db.events.find({"technique": {"$ne": None}})}
    planted = list(db.decoys.find({"policy": {"$ne": "static"}, "session_id": {"$ne": "environment"}}))
    touched = [d for d in db.decoys.find({}) if d.get("touched_by")]
    m = {"policy": policy, "seed": seed, "attacker": attacker, "elapsed_s": elapsed, "commands": res.commands,
         "hosts_entered": len(res.entered_hosts), "techniques_observed": len(techs),
         "techniques": sorted(techs), "decoys_planted": len(planted),
         "decoys_touched": len(touched), "injection_alerts": db.alerts.count_documents({"type": "injection_attempt"}),
         "canary_uses": db.events.count_documents({"event_type": "canary_use"}),
         "trap_hits": db.events.count_documents({"event_type": "trap_hit"}),
         "doc_retrievals": db.events.count_documents({"event_type": "doc_retrieval"}),
         "egress": db.events.count_documents({"event_type": "egress"}),
         "pending_approvals": db.actions.count_documents({"status": "pending"})}
    db.runs.insert_one({"run_id": f"r-{policy}-{seed}", **m})
    return m


def cmd_attack(ctx, args):
    run_attack(ctx, args.policy, args.seed, args.pace, args.attacker)


def cmd_compare(ctx, args):
    rows = [run_attack(ctx, p, args.seed, args.pace, args.attacker) for p in ("static", "agent")]
    cols = [("policy", "policy"), ("commands", "cmds"), ("hosts_entered", "hosts"),
            ("techniques_observed", "techniques"), ("decoys_planted", "planted"),
            ("decoys_touched", "touched"), ("injection_alerts", "injection"), ("canary_uses", "canary")]
    print("\n=== static vs agent (seed {}) ===".format(args.seed))
    print("  " + "".join(f"{h:>11}" for _, h in cols))
    for r in rows:
        print("  " + "".join(f"{str(r[k]):>11}" for k, _ in cols))


def cmd_reset(ctx, args):
    if args.all:
        for c in ATTACK_COLLECTIONS + ["decoys", "environments", "world_model", "canaries", "memory", "learning_history"]:
            ctx.db[c].delete_many({})
        import shutil
        for sub in ("deception", "render", "decoys"):
            shutil.rmtree(DATA / sub, ignore_errors=True)
        print("everything cleared.")
    else:
        _reset_attack(ctx)
        print("attack data cleared; environment kept.")


def cmd_status(ctx, args):
    db = ctx.db
    env = db.world_model.find_one({"_id": "current"})
    print("mongo:", "ok")
    print("environment:", env["company"] if env else "none",
          "| hosts:", [h["hostname"] for h in env["hosts"]] if env else [])
    print("events:", db.events.count_documents({}), "| sessions:", len(db.events.distinct("session_id")),
          "| decoys planted:", db.decoys.count_documents({"session_id": {"$ne": "environment"}}),
          "| alerts:", db.alerts.count_documents({}), "| pending approvals:", db.actions.count_documents({"status": "pending"}))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="local.run")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup"); s.add_argument("--brief", default=""); s.add_argument("--force", action="store_true")
    a = sub.add_parser("attack"); a.add_argument("--policy", choices=["static", "agent"], default="agent")
    a.add_argument("--attacker", default="auto", choices=["auto", "sweep", "data_thief", "red_team", "apt", "injector", "victim", "mcp_poison", "rag_thief", "evasive", "crawler"])
    a.add_argument("--seed", type=int, default=1); a.add_argument("--pace", type=float, default=0.4)
    c = sub.add_parser("compare"); c.add_argument("--seed", type=int, default=1); c.add_argument("--pace", type=float, default=0.4)
    c.add_argument("--attacker", default="auto", choices=["auto", "sweep", "data_thief", "red_team", "apt", "injector", "victim", "mcp_poison", "rag_thief", "evasive", "crawler"])
    r = sub.add_parser("reset"); r.add_argument("--all", action="store_true")
    sub.add_parser("status")
    args = ap.parse_args(argv)
    ctx = context()
    {"setup": cmd_setup, "attack": cmd_attack, "compare": cmd_compare, "reset": cmd_reset, "status": cmd_status}[args.cmd](ctx, args)


if __name__ == "__main__":
    main()
