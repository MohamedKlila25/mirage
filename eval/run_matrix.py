"""Run the experiment matrix (one AI attacker vs static and agent, over several seeds) and produce
the static-vs-agent comparison for the 30% criterion, plus the reliability/control numbers.

  python -m eval.run_matrix --attacker data_thief --seeds 1,2,3
Outputs: eval/out/results.json, report.md, and PNG charts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from local.run import DATA, context, run_attack
from .metrics import RELIAB, compare_table, full_metrics

OUT = Path(__file__).resolve().parent / "out"


def run_matrix(attacker: str, seeds: list[int], policies=("static", "agent"), pace: float = 0.5) -> list[dict]:
    ctx = context()
    records = []
    for seed in seeds:
        for policy in policies:
            print(f"\n### {policy} vs {attacker} seed={seed}")
            m = run_attack(ctx, policy, seed, pace, attacker)
            rel = full_metrics(ctx.db, DATA / "control-audit.jsonl")
            rec = {**m, **rel}
            rec.pop("techniques", None)
            records.append(rec)
            ctx.db["eval_runs"].update_one({"run_id": f"{attacker}-{policy}-{seed}"},
                                           {"$set": {"run_id": f"{attacker}-{policy}-{seed}", **rec}}, upsert=True)
    return records


def _print_table(rows):
    w = [max(len(str(r[c])) for r in rows) for c in range(len(rows[0]))]
    for i, r in enumerate(rows):
        print("  " + "  ".join(str(c).ljust(w[j]) for j, c in enumerate(r)))
        if i == 0:
            print("  " + "  ".join("-" * w[j] for j in range(len(r))))


def _charts(records, attacker):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from statistics import median
    OUT.mkdir(parents=True, exist_ok=True)
    policies = ["static", "agent"]
    colors = {"static": "#6b7280", "agent": "#2dd98f"}
    bg, fg = "#0d0d10", "#e8e8ea"

    def med(pol, key):
        v = [r[key] for r in records if r["policy"] == pol and r.get(key) is not None]
        return median(v) if v else 0

    # effectiveness bars — lead with what the adaptive agent changes
    keys = [("hosts_entered", "hosts\nbreached"), ("decoys_planted", "decoys\nplanted"),
            ("decoys_touched", "decoys\ntaken"), ("techniques_observed", "ATT&CK"),
            ("canary_uses", "canary\nhits")]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = range(len(keys)); wdt = 0.38
    for i, pol in enumerate(policies):
        ax.bar([xi + (i - .5) * wdt for xi in x], [med(pol, k) for k, _ in keys], wdt,
               label=pol, color=colors[pol], edgecolor="none")
    ax.set_xticks(list(x)); ax.set_xticklabels([l for _, l in keys], color=fg, fontsize=9)
    ax.set_title(f"Defensive effectiveness — static vs agent ({attacker})", color=fg, fontsize=11)
    _style(ax, fig, bg, fg); ax.legend(facecolor=bg, edgecolor="#333", labelcolor=fg)
    fig.tight_layout(); fig.savefig(OUT / "effectiveness.png", dpi=130); plt.close(fig)

    # breadcrumb engagement (agent): touched / planted per seed
    agent = [r for r in records if r["policy"] == "agent"]
    if agent:
        fig, ax = plt.subplots(figsize=(6, 3.6))
        seeds = [r["seed"] for r in agent]
        eng = [100 * r["decoys_touched"] / max(r["decoys_planted"], 1) for r in agent]
        ax.bar([str(s) for s in seeds], eng, color=colors["agent"], edgecolor="none")
        ax.set_ylabel("engagement %", color=fg); ax.set_xlabel("seed", color=fg)
        ax.set_title("Breadcrumb engagement (agent): decoys touched / planted", color=fg, fontsize=11)
        _style(ax, fig, bg, fg); fig.tight_layout(); fig.savefig(OUT / "engagement.png", dpi=130); plt.close(fig)


def _style(ax, fig, bg, fg):
    fig.patch.set_facecolor(bg); ax.set_facecolor(bg)
    for s in ax.spines.values():
        s.set_color("#333")
    ax.tick_params(colors=fg); ax.yaxis.label.set_color(fg)
    ax.grid(axis="y", color="#222", linewidth=.6)


def _report(records, table, attacker):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")
    md = [f"# Mirage — experiment results ({attacker})\n",
          f"{len([r for r in records if r['policy']=='static'])} static runs, "
          f"{len([r for r in records if r['policy']=='agent'])} agent runs. "
          "Median [min–max] across seeds.\n", "| " + " | ".join(table[0]) + " |",
          "| " + " | ".join("---" for _ in table[0]) + " |"]
    md += ["| " + " | ".join(str(c) for c in r) + " |" for r in table[1:]]
    md += ["\n![effectiveness](effectiveness.png)\n", "![engagement](engagement.png)\n"]
    (OUT / "report.md").write_text("\n".join(md), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="eval.run_matrix")
    ap.add_argument("--attacker", default="data_thief", choices=["data_thief", "injector", "victim"])
    ap.add_argument("--seeds", default="1,2,3")
    ap.add_argument("--pace", type=float, default=0.5)
    a = ap.parse_args(argv)
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    records = run_matrix(a.attacker, seeds, pace=a.pace)
    table = compare_table(records)
    print(f"\n=== static vs agent ({a.attacker}, seeds {seeds}) ===")
    _print_table(table)
    try:
        _charts(records, a.attacker)
    except Exception as e:
        print("  (charts skipped:", type(e).__name__, str(e)[:80], ")")
    _report(records, table, a.attacker)
    print(f"\nwrote eval/out/report.md, results.json, charts")


if __name__ == "__main__":
    main()
