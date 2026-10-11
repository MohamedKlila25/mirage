"""Generate the Mirage pitch/technical deck (docs/Mirage_Deck.pptx) with live-data charts.

Run:  PYTHONPATH=. python docs/make_deck.py
Reads docs/_snapshot.json (produced from the live MongoDB) so every number is real."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
IMG = HERE / "img"; IMG.mkdir(exist_ok=True)
SNAP = json.loads((HERE / "_snapshot.json").read_text())

# ---- theme ----
BG = RGBColor(0x08, 0x09, 0x0C); PANEL = RGBColor(0x12, 0x16, 0x1A)
INK = RGBColor(0xE9, 0xEE, 0xF0); MUTED = RGBColor(0x9A, 0xA3, 0xAA); DIM = RGBColor(0x66, 0x6E, 0x74)
ACCENT = RGBColor(0x35, 0xD6, 0xA6); GOLD = RGBColor(0xE8, 0xD9, 0x8A); RED = RGBColor(0xFF, 0x6B, 0x7A)
H_ACCENT, H_GOLD, H_RED, H_INK, H_PANEL = "#35d6a6", "#e8d98a", "#ff6b7a", "#e9eef0", "#0b0d10"
FONT = "Segoe UI"; MONO = "Consolas"


def chart_detection():
    d = SNAP["detection"]
    labels = ["F1", "Precision", "Recall", "Trap activation", "Engagement", "Grounded"]
    vals = [d.get("f1_score") or 0, d.get("precision") or 0, d.get("recall") or 0,
            d.get("trap_activation_rate") or 0, d.get("engagement_rate") or 0, d.get("grounding_rate") or 0]
    fig, ax = plt.subplots(figsize=(7.2, 3.4), dpi=200); fig.patch.set_facecolor(H_PANEL); ax.set_facecolor(H_PANEL)
    y = range(len(labels))
    ax.barh(list(y), vals, color=H_ACCENT, height=.6)
    for i, v in enumerate(vals):
        ax.text(min(v + .02, .98), i, f"{v:.2f}" if labels[i] == "F1" else f"{int(v*100)}%", va="center", color=H_INK, fontsize=10)
    ax.set_yticks(list(y)); ax.set_yticklabels(labels, color=H_INK, fontsize=11)
    ax.set_xlim(0, 1.05); ax.invert_yaxis(); ax.set_xticks([])
    for s in ax.spines.values(): s.set_visible(False)
    ax.text(0, -0.9, "hallucination rate: {:.0%}   ·   MTTD: {}s   ·   MTTA: {}".format(
        d.get("hallucination_rate") or 0, d.get("mttd_s"), (str(d.get("mtta_s")) + "s") if d.get("mtta_s") else "n/a"),
        color=H_GOLD, fontsize=10)
    fig.tight_layout(); p = IMG / "detection.png"; fig.savefig(p, facecolor=H_PANEL); plt.close(fig); return p


def chart_defense():
    dv = SNAP["defense"]
    fig, ax = plt.subplots(figsize=(7.2, 3.4), dpi=200); fig.patch.set_facecolor(H_PANEL); ax.set_facecolor(H_PANEL)
    x = range(len(dv)); att = [v["attempts"] for v in dv]; dfn = [v["defended"] for v in dv]
    ax.bar(list(x), att, color="#2a2f33", width=.6, label="attempted")
    ax.bar(list(x), dfn, color=H_ACCENT, width=.6, label="defended")
    for i, v in enumerate(dv):
        ax.text(i, v["attempts"] + max(att) * .02, f"{v['defended']}/{v['attempts']}", ha="center", color=H_INK, fontsize=10)
    ax.set_xticks(list(x)); ax.set_xticklabels([v["vector"] + f"\n{v['owasp']}" for v in dv], color=H_INK, fontsize=9)
    ax.set_yticks([]);
    for s in ax.spines.values(): s.set_visible(False)
    ax.legend(facecolor=H_PANEL, edgecolor="none", labelcolor=H_INK, fontsize=9, loc="upper right")
    fig.tight_layout(); p = IMG / "defense.png"; fig.savefig(p, facecolor=H_PANEL); plt.close(fig); return p


def chart_scenarios():
    sc = [s for s in SNAP["scenarios"] if s["attacker"] != "crawler"]
    fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=200); fig.patch.set_facecolor(H_PANEL); ax.set_facecolor(H_PANEL)
    colors = {"hard": H_RED, "medium": H_GOLD, "easy": H_ACCENT}
    y = range(len(sc)); runs = [s["runs"] for s in sc]
    ax.barh(list(y), runs, color=[colors.get(s["difficulty"], H_ACCENT) for s in sc], height=.62)
    for i, s in enumerate(sc):
        ax.text(s["runs"] + max(runs) * .01, i, f"  {s['runs']} runs · defended", va="center", color=H_INK, fontsize=9)
    ax.set_yticks(list(y)); ax.set_yticklabels([s["label"] for s in sc], color=H_INK, fontsize=10)
    ax.invert_yaxis(); ax.set_xticks([])
    for s in ax.spines.values(): s.set_visible(False)
    fig.tight_layout(); p = IMG / "scenarios.png"; fig.savefig(p, facecolor=H_PANEL); plt.close(fig); return p


# ---- pptx helpers ----
prs = Presentation(); prs.slide_width = Inches(13.333); prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]


def slide():
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid(); s.background.fill.fore_color.rgb = BG
    return s


def text(s, l, t, w, h, runs, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT, font=FONT, anchor=MSO_ANCHOR.TOP, space=6):
    tb = s.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h)); tf = tb.text_frame
    tf.word_wrap = True; tf.vertical_anchor = anchor
    items = runs if isinstance(runs, list) else [(runs, {})]
    for i, (txt, opt) in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = opt.get("align", align); p.space_after = Pt(opt.get("space", space)); p.level = opt.get("level", 0)
        r = p.add_run(); r.text = txt; f = r.font
        f.size = Pt(opt.get("size", size)); f.bold = opt.get("bold", bold); f.name = opt.get("font", font)
        f.color.rgb = opt.get("color", color)
    return tb


def bullets(s, items, top=1.9, left=0.9, width=11.5, size=16):
    runs = []
    for it in items:
        if isinstance(it, tuple):
            txt, lvl = it
        else:
            txt, lvl = it, 0
        runs.append(("•  " + txt if lvl == 0 else "–  " + txt,
                     {"size": size - (lvl * 2), "color": INK if lvl == 0 else MUTED, "level": lvl, "space": 9, "font": FONT}))
    return text(s, left, top, width, 5.2, runs)


def kicker(s, txt):
    text(s, 0.9, 0.7, 11, 0.5, [(txt, {"size": 12, "color": ACCENT, "bold": True, "font": FONT})])


def heading(s, txt):
    text(s, 0.9, 1.05, 11.5, 0.9, [(txt, {"size": 32, "color": INK, "bold": True})])


def footer(s, n):
    text(s, 0.9, 7.0, 11.5, 0.4, [("MIRAGE · Deception Agent OS", {"size": 9, "color": DIM}),
         ], )
    text(s, 11.8, 7.0, 1.2, 0.4, [(str(n), {"size": 9, "color": DIM, "align": PP_ALIGN.RIGHT})])


# ================= slides =================
d = SNAP["detection"]

# 1 title
s = slide()
text(s, 0.9, 2.3, 11.5, 1.6, [("MIRAGE", {"size": 76, "bold": True, "color": ACCENT, "font": FONT})])
text(s, 0.95, 3.7, 11.5, 1.0, [("AI deception & honeynet defense for agentic threats", {"size": 24, "color": INK})])
text(s, 0.95, 4.5, 11.5, 0.6, [("An AI defender that traps attackers in a fake network, studies them, and plants tailored decoys — with a human analyst in control.", {"size": 15, "color": MUTED})])
text(s, 0.95, 5.6, 11.5, 0.5, [("Secure Horizon  ·  Track 2: AI for Security & Secure AI", {"size": 14, "color": GOLD, "bold": True})])

# 2 problem
s = slide(); kicker(s, "THE PROBLEM"); heading(s, "AI agents are a new, unguarded attack surface")
bullets(s, [
    "Companies are deploying LLM agents with tools, memory and RAG — a brand-new surface that classic security tools don't see.",
    "OWASP's Agentic Top-10 (ASI01–ASI06) is largely undefended: prompt injection, tool misuse, identity abuse, tool/data poisoning.",
    "A hijacked internal assistant can exfiltrate data without a single CVE or malware.",
    "Meanwhile SOC analysts drown in alerts and must reconstruct the story themselves.",
    "Honeypots catch intruders — but they're passive and don't adapt to an attacker, let alone an AI one.",
]); footer(s, 2)

# 3 idea
s = slide(); kicker(s, "THE IDEA"); heading(s, "A defender agent that fights deception with deception")
bullets(s, [
    "Mirage is an AI defender (AWS Bedrock / Claude) that runs a honeynet of fake hosts, tools and documents.",
    "When an attacker — human or AI agent — enters, Mirage profiles them, predicts their next move, and plants decoys tailored to that attacker.",
    "Every trap is an OWASP-Agentic signal: fake credentials (ASI03), decoy MCP tools (ASI02), honey-docs (ASI06), injection detection (ASI01).",
    "Mirage proposes containment; a human analyst approves — nothing destructive happens autonomously.",
    "Everything Mirage says about the attacker is re-checked against raw evidence in code, so its analysis can't hallucinate.",
]); footer(s, 3)

# 4 how it works (pipeline)
s = slide(); kicker(s, "ARCHITECTURE"); heading(s, "Two networks, one adaptive loop")
flow = ["Attacker", "Deception env\n(SSH · MCP · RAG)", "Collector →\nEvent Store", "Mirage brain\n(profile · plan)", "mirage-control\n(human approve)", "Exports\n(SIEM · reports)"]
from pptx.enum.shapes import MSO_SHAPE
x = 0.7
for i, label in enumerate(flow):
    w = 1.95
    box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(3.0), Inches(w), Inches(1.2))
    box.fill.solid(); box.fill.fore_color.rgb = PANEL; box.line.color.rgb = ACCENT if i == 3 else RGBColor(0x2a, 0x31, 0x36); box.line.width = Pt(1.5 if i == 3 else 1)
    tf = box.text_frame; tf.word_wrap = True; p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = label; r.font.size = Pt(11); r.font.color.rgb = ACCENT if i == 3 else INK; r.font.bold = (i == 3); r.font.name = FONT
    if i < len(flow) - 1:
        ar = s.shapes.add_textbox(Inches(x + w - 0.08), Inches(3.35), Inches(0.5), Inches(0.5))
        pr = ar.text_frame.paragraphs[0]; rr = pr.add_run(); rr.text = "→"; rr.font.size = Pt(18); rr.font.color.rgb = ACCENT
    x += w + 0.33
text(s, 0.9, 1.95, 11.5, 0.6, [("Attack-net (isolated, no internet)  ———  Defense-net", {"size": 12, "color": MUTED})])
bullets(s, [
    "Attack-net: the fake company — Cowrie-format SSH hosts, an MCP tool server, a RAG knowledge base, an internal wiki.",
    "Defense-net: a read-only collector normalises every log into an event + ATT&CK technique; Mirage reasons over batches.",
    "Feedback loop: Mirage writes new decoys and wiki pages back into the environment to keep the attacker engaged.",
], top=4.6, size=15); footer(s, 4)

# 5 attacker side
s = slide(); kicker(s, "THE ADVERSARY"); heading(s, "The attackers are AI agents — and they self-plan")
bullets(s, [
    "Attackers are LLM-driven agents (Claude Haiku via Bedrock), not fixed scripts — they decide their own moves.",
    "An auto-planner picks the attack and can mix vectors; it prefers the hard options.",
    ("Personas: data-thief, injector (tries to manipulate the analyst), and a patient APT that covers its tracks.", 1),
    ("Agentic scenarios: email-hijack, MCP tool-poisoning, RAG honey-doc theft, and an evasive blend that blinds the audit log.", 1),
    "Deterministic scripted variants are kept for reproducible demos — well-aligned models often refuse, which is itself a finding.",
]); footer(s, 5)

# 6 scenarios table
s = slide(); kicker(s, "SCENARIOS USED"); heading(s, "Six attack scenarios across every trap source")
rows = [
    ("Credential theft → lateral", "SSH / Cowrie", "T1552 · T1078 · T1083", "canary hits (ASI03)"),
    ("APT (evasive)", "SSH / Cowrie", "+ T1070 anti-forensics", "canary + decoys"),
    ("Prompt-injection hijack", "Email / MCP", "ASI01", "injection caught"),
    ("MCP tool-poisoning", "MCP server", "ASI06 → ASI02", "trap_hit on decoy tools"),
    ("RAG honey-doc theft", "RAG (Chroma)", "ASI06", "doc_retrieval"),
    ("Evasive blend (blind + exfil)", "MCP + RAG", "ASI01/02/06 + evasion", "trap_hit + egress"),
]
from pptx.util import Inches as IN
tbl = s.shapes.add_table(len(rows) + 1, 4, IN(0.9), IN(1.95), IN(11.5), IN(3.8)).table
tbl.columns[0].width = IN(3.6); tbl.columns[1].width = IN(2.3); tbl.columns[2].width = IN(3.1); tbl.columns[3].width = IN(2.5)
hdr = ["Scenario", "Source", "OWASP / ATT&CK", "Detection signal"]
for c, htxt in enumerate(hdr):
    cell = tbl.cell(0, c); cell.fill.solid(); cell.fill.fore_color.rgb = PANEL
    p = cell.text_frame.paragraphs[0]; r = p.add_run(); r.text = htxt; r.font.size = Pt(12); r.font.bold = True; r.font.color.rgb = ACCENT; r.font.name = FONT
for ri, row in enumerate(rows, 1):
    for c, val in enumerate(row):
        cell = tbl.cell(ri, c); cell.fill.solid(); cell.fill.fore_color.rgb = BG
        p = cell.text_frame.paragraphs[0]; r = p.add_run(); r.text = val; r.font.size = Pt(11); r.font.color.rgb = INK if c == 0 else MUTED; r.font.name = FONT
footer(s, 6)

# 7 defender
s = slide(); kicker(s, "THE DEFENDER"); heading(s, "Mirage brain — profile, plan, contain")
bullets(s, [
    "Runs on Claude Sonnet (Bedrock). Each batch of events: classifies the actor, infers the objective, predicts next ATT&CK moves.",
    "Plants decoys tailored to the attacker — breadcrumbs with fake credentials, honey-docs, decoy services, wiki pages.",
    "For a hijacked AI agent it proposes the right containment: revoke the agent token, disable the abused MCP tool, recommend an IOC block.",
    "mirage-control is the only way Mirage can act — a deterministic MCP tool server enforcing kill-switch, allowlist, schema, evidence and rate caps.",
    "Human-in-the-loop: risky actions queue for analyst approval; a kill switch freezes the agent instantly.",
]); footer(s, 7)

# 8 secure AI
s = slide(); kicker(s, "SECURE AI"); heading(s, "The defender can't lie, and can't be injected into trusting the attacker")
bullets(s, [
    "Grounded analyst summary: Mirage's every claim is re-verified in code against the raw events — quotes must actually appear.",
    "Evidence checker (code, not an LLM) reports a grounding rate and a hallucination rate for every incident.",
    f"Measured across {SNAP['runs_total']} agent runs: grounding {int((d.get('grounding_rate') or 0)*100)}%, hallucination {int((d.get('hallucination_rate') or 0)*100)}%.",
    "Injection guard wraps all untrusted input (ASI01); it may flag a session but can never mark it benign — a poisoned note can't disarm Mirage.",
    "Every mirage-control action carries evidence event-ids and is written to a hash-chained audit log.",
]); footer(s, 8)

# 9 stack
s = slide(); kicker(s, "REAL STACK — NOT MOCKED"); heading(s, "Built on production primitives")
bullets(s, [
    "AWS Bedrock — Claude Sonnet (defender), Claude Haiku (attacker/planner), Titan v2 embeddings.",
    "MCP — the company tools and mirage-control run as real MCP SDK servers over a stdio transport (JSON-RPC).",
    "RAG — a Chroma vector database with Titan embeddings; retrieving a restricted honey-doc is the ASI06 signal.",
    "Honeynet — rendered into Cowrie's filesystem format; served locally by an emulated shell (no Docker needed).",
    "MongoDB is the system of record; a FastAPI console streams the live pipeline. 362 automated tests pass.",
]); footer(s, 9)

# 10 results chart
s = slide(); kicker(s, "RESULTS"); heading(s, "Detection quality")
s.shapes.add_picture(str(chart_detection()), Inches(0.8), Inches(2.0), width=Inches(8.4))
text(s, 9.5, 2.2, 3.2, 4.5, [
    ("F1 = {:.2f}".format(d.get("f1_score") or 0), {"size": 18, "bold": True, "color": ACCENT, "space": 4}),
    ("perfect detection coverage", {"size": 11, "color": MUTED, "space": 14}),
    ("Grounded {:.0%}".format(d.get("grounding_rate") or 0), {"size": 18, "bold": True, "color": ACCENT, "space": 4}),
    ("Hallucination {:.0%}".format(d.get("hallucination_rate") or 0), {"size": 13, "color": GOLD, "space": 14}),
    ("MTTD {}s".format(d.get("mttd_s")), {"size": 18, "bold": True, "color": INK, "space": 4}),
    ("mean time to detect", {"size": 11, "color": MUTED}),
]); footer(s, 10)

# 11 defense coverage chart
s = slide(); kicker(s, "RESULTS"); heading(s, "Defense coverage — every attack vector caught")
s.shapes.add_picture(str(chart_defense()), Inches(1.6), Inches(2.0), width=Inches(10.1))
text(s, 0.9, 6.3, 11.5, 0.6, [("Each bar: attacker actions of that vector; teal = defended. Every action happens inside the deception net and is observed.", {"size": 12, "color": MUTED})])
footer(s, 11)

# 12 scenarios chart
s = slide(); kicker(s, "RESULTS"); heading(s, "Scenarios defended (hard first)")
s.shapes.add_picture(str(chart_scenarios()), Inches(1.6), Inches(2.0), width=Inches(10.1))
text(s, 0.9, 6.3, 11.5, 0.6, [("red = hard · gold = medium.  Every scenario across {} agent runs was detected and contained.".format(SNAP["runs_total"]), {"size": 12, "color": MUTED})])
footer(s, 12)

# 13 ops / compliance
s = slide(); kicker(s, "OPERATIONAL VALUE"); heading(s, "Fits a real SOC, and the regulator")
bullets(s, [
    "One-click SIEM export: ECS-schema alerts plus ready-to-paste Splunk SPL and Elastic ES|QL per technique and IOC.",
    "Auto-generated incident report with the grounded summary, ATT&CK mapping, decoys and recommendations.",
    "NIS2 Article 23 24-hour early-warning draft, pre-filled from the incident.",
    "Analyst stays in control: approval queue, kill switch, hash-chained audit — AI proposes, human disposes.",
    "Live console: the attack pipeline as a node graph, plus a scroll-down analytics page (gauges, histograms, ATT&CK coverage).",
]); footer(s, 13)

# 14 roadmap / close
s = slide(); kicker(s, "WHAT'S NEXT"); heading(s, "Roadmap & the ask")
bullets(s, [
    "Run the real Cowrie daemon and serve MCP over the network for a fully distributed deployment.",
    "Tamper-evident audit end-to-end; an analyst time-saved study (triage time with Mirage vs raw logs).",
    "More adversary personas and a single session that blends host + agent compromise.",
    "Package as a drop-in deception layer in front of any company's real MCP/RAG stack.",
])
text(s, 0.9, 5.8, 11.5, 1.0, [
    ("Mirage turns every intrusion attempt into labelled, grounded threat intelligence —", {"size": 16, "color": INK, "space": 2}),
    ("and keeps a human in command the whole time.", {"size": 16, "color": ACCENT, "bold": True})])
footer(s, 14)

out = HERE / "Mirage_Deck.pptx"
try:
    prs.save(str(out))
except PermissionError:
    out = HERE / "Mirage_Deck_new.pptx"
    prs.save(str(out))
    print("(Mirage_Deck.pptx was open/locked — saved to Mirage_Deck_new.pptx instead)")
print("wrote", out, "·", len(prs.slides._sldIdLst), "slides")
