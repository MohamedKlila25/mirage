"""Run: python demo.py   (no AWS needed: the three LLM answers are replayed from scenario.py)

Shows what the jury asks for in 'AI reliability & control':
hallucinations caught, manipulation caught, human in the loop, tamper-evident trace.
"""
import json
import tempfile
from pathlib import Path

from reliability import AuditLog, PolicyConfig, ReliabilityGate
from scenario import (ATTACK_EVENTS, BENIGN_EVENTS, CLEAN_EVENTS, GOOD_OUTPUT, HALLUCINATED_OUTPUT,
                      MANIPULATED_OUTPUT, OTHER_SESSION_EVENT, SESSION, as_llm_text)

tmp = Path(tempfile.mkdtemp())
cfg = PolicyConfig(kill_switch_file=str(tmp / "kill"))
gate = ReliabilityGate(cfg, AuditLog(tmp / "audit.jsonl"), BENIGN_EVENTS)


def show(title, r):
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")
    print(f"session confidence: {r.session_confidence:.2f}   escalate to analyst: {r.escalate}")
    for reason in r.escalation_reasons:
        print(f"  ! {reason}")
    for a in r.alerts:
        print(f"  ALERT {a['type']} ({a['owasp']}) {a.get('event_id', '')} {a.get('patterns', a.get('detail', ''))}")
    print("claims:")
    for c in r.claims:
        print(f"  {c.status:11} {c.kind:9} {c.ref:12} conf {c.claimed_confidence:.2f} -> {c.confidence:.2f}  {'; '.join(c.reasons)}")
    for a in r.auto_actions:
        print(f"  AUTO      {a['tool']} {a['params']}")
    for a in r.escalated_actions:
        print(f"  ESCALATED {a['tool']} {a['params']}  ({'; '.join(a['reasons'])})")
    for p in r.pending_proposals:
        v = p["validation"]
        val = f" | tested: fires on {v['attack_hits']}, benign hits {len(v['benign_hits'])}" if v else ""
        print(f"  PENDING   {p['proposal_id']} {p['type']} {p['technique'] or ''}{val}")
        for f in p["escalation_flags"]:
            print(f"              flag: {f}")
    for x in r.rejected:
        print(f"  REJECTED  {x.get('type') or x.get('tool')}: {x['reasons'][0][:110]}")


show("1. Honest LLM answer, clean session", gate.process(SESSION, CLEAN_EVENTS, as_llm_text(GOOD_OUTPUT)))
show("2. Hallucinating LLM answer", gate.process(SESSION, ATTACK_EVENTS + [OTHER_SESSION_EVENT], as_llm_text(HALLUCINATED_OUTPUT)))
show("3. LLM fooled by the attacker's injected note", gate.process(SESSION, ATTACK_EVENTS, as_llm_text(MANIPULATED_OUTPUT)))

print(f"\n{'=' * 78}\n4. Traceability\n{'=' * 78}")
gate.record_analyst_decision(SESSION, "p-demo", "reject", "analyst-1", reason="rule too narrow")
print("audit records:", len(gate.audit.records()), "| chain valid:", gate.audit.verify())
print("everything that used evt-0004:", [r["kind"] for r in gate.audit.trace("evt-0004")])
lines = (tmp / "audit.jsonl").read_text().splitlines()
rec = json.loads(lines[2]); rec["kind"] = "action_auto_tampered"; lines[2] = json.dumps(rec)
(tmp / "audit.jsonl").write_text("\n".join(lines) + "\n")
print("after editing record #2 by hand -> chain valid:", gate.audit.verify())
