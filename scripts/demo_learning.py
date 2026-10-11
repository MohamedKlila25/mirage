"""Proof that Mirage LEARNS — a small model (Nova Micro) + cross-session memory.

An adversary-emulation sweep reveals more ATT&CK techniques each round (incremental); round 1 runs with
memory OFF (cold start), rounds 2+ with memory ON, so Mirage folds each technique into its memory and reuses
similar past cases. Knowledge coverage and past-cases-reused climb over the rounds. Needs Bedrock.

Usage:  PYTHONPATH=. python scripts/demo_learning.py
Then open the dashboard -> "Mirage is learning".
"""
import os

# use a SMALL model so Mirage starts weak and leans on its memory (Claude Sonnet is too strong to show a gain)
os.environ.setdefault("MIRAGE_DEFENDER_MODEL", "us.amazon.nova-micro-v1:0")

from brain.learning import reset_learning
from local.run import context, run_attack

# reveal more ATT&CK techniques each round (incremental sweep) -> a smooth, climbing knowledge curve
LIMITS = [4, 8, 12, 16, 20, 24, 28, 32, 38, 44]

ctx = context()
reset_learning(ctx.db)
print(f"defender model: {os.environ['MIRAGE_DEFENDER_MODEL']}  ·  attacker: sweep (revealing more techniques each round)\n")
for i, lim in enumerate(LIMITS, 1):
    os.environ["MIRAGE_MEMORY"] = "off" if i == 1 else "on"
    os.environ["MIRAGE_SWEEP_LIMIT"] = str(lim)
    try:
        run_attack(ctx, "agent", 7, 0.1, "sweep")
    except Exception as e:
        print(f"  round {i} FAILED: {type(e).__name__} {e}")
        continue
    pt = ctx.db["learning_history"].find_one(sort=[("run", -1)]) or {}
    print(f"  round {i}  [mem {'off' if i==1 else 'on':3} · {lim:2} techs]  coverage {int((pt.get('knowledge_coverage') or 0)*100):3}%  "
          f"techniques learned {pt.get('learned')}  cases reused {pt.get('cases_used', 0)}")
os.environ["MIRAGE_MEMORY"] = "on"
os.environ.pop("MIRAGE_SWEEP_LIMIT", None)
print("\ndone - open the dashboard, scroll to 'Mirage is learning'.")
