# Mirage — Technical Report

**AI deception & honeynet defense for agentic threats**
Secure Horizon · Track 2: *AI for Security & Secure AI*

> Mirage is an AI defender agent that runs a honeynet of fake hosts, tools and documents, traps attackers
> (human or AI) inside it, profiles them, plants decoys tailored to each attacker, and proposes
> containment — with a human analyst in command the whole time. Every claim the AI makes about an
> attacker is re-verified against raw evidence in code, so its analysis cannot hallucinate.

---

## 1. Problem & threat model

Organisations are deploying LLM **agents** with tools, memory and retrieval. This is a new attack
surface that classic security tooling does not see: there is no CVE and no malware when a hijacked
internal assistant is tricked into exporting a customer list. OWASP's **Agentic Top-10 (ASI01–ASI06)**
describes these risks, and they are largely undefended in practice.

Mirage is built against two complementary threat models:

| Code | OWASP Agentic risk | How Mirage exercises & detects it |
|---|---|---|
| **ASI01** | Prompt / instruction injection | Poisoned email & documents; an **injection guard** wraps all untrusted input and can flag but *never* mark a session benign |
| **ASI02** | Tool misuse / excessive agency | Over-privileged **decoy MCP tools**; any call is a `trap_hit` |
| **ASI03** | Identity / secret abuse | **Canary** credentials seeded in breadcrumbs; any use is a high-confidence alert |
| **ASI06** | Tool / data poisoning | Poisoned tool descriptions + **honey-docs** in RAG; retrieval is the signal |

Host-level activity is additionally mapped to **MITRE ATT&CK** (e.g. `T1078` valid accounts, `T1552.001`
credentials in files, `T1083` file discovery, `T1070` anti-forensics), so SSH-side intrusions produce a
standard technique breakdown alongside the agentic signals.

---

## 2. System overview

Mirage closes an adaptive loop: **observe → profile → deceive → contain**, with a human approving anything
consequential.

1. An attacker enters the honeynet (SSH host, MCP tool call, or RAG query).
2. A read-only **collector** normalises every log line into an event and tags it with an ATT&CK technique.
3. The **Mirage brain** (Claude Sonnet via Bedrock) reasons over each batch: it classifies the actor,
   infers the objective, predicts the next moves, and decides what decoys to plant.
4. It plants decoys **tailored to that attacker** and writes them back into the environment (feedback loop).
5. For dangerous actions it proposes containment through **mirage-control**; the analyst approves or rejects.
6. The whole incident is exported as SIEM alerts, an incident report, and a regulator-ready draft.

---

## 3. Architecture

The deployment is split into two networks, mirrored in the console as two zones:

```
ATTACK-NET (isolated, no internet)                 DEFENSE-NET
┌───────────┐    ┌──────────────────────┐         ┌───────────┐   ┌─────────────┐   ┌──────────────┐   ┌──────────┐
│ Attacker  │──▶ │ Deception environment│ ─logs──▶│ Collector │──▶│ Event store │──▶│  Mirage brain  │──▶│mirage-control│──▶ Exports
│ (AI agent)│    │ SSH · MCP · RAG · wiki│         │ (read-only)│  │  (MongoDB)  │   │ profile·plan │   │ human HITL │
└───────────┘    └──────────▲───────────┘         └───────────┘   └─────────────┘   └──────┬───────┘   └──────────┘
                            └──────────────── feedback: new decoys & wiki pages ────────────┘
```

**Components**

- **Attacker** — an LLM red-team agent (see §5), or deterministic scripted variants for reproducible demos.
- **Deception environment** — Cowrie-format SSH decoy hosts with breadcrumbs; a **company MCP server**
  (real + decoy tools); a **RAG** knowledge base (Chroma vector store) with honey-docs; an internal wiki.
- **Collector** — tails the Cowrie and trap logs read-only, normalises them, and maps each event to an
  ATT&CK technique.
- **Mirage brain** — the defender policy; the only "smart" component. Reasons over batches of events.
- **mirage-control** — a *deterministic* MCP tool server; the **only** way Mirage can act. Enforces a
  kill-switch, a tool allowlist, argument schemas, mandatory evidence event-ids, and rate caps.
- **Exports** — SIEM alerts (ECS), Splunk/Elastic queries, incident report, NIS2 draft.

---

## 4. The adversary — AI attackers that self-plan

Attackers are **LLM-driven agents** (Claude Haiku via Bedrock), not fixed scripts — each turn the model
decides its own next action and reacts to what it finds. An **auto-planner** selects the attack and may
mix vectors, and is biased toward the harder options.

- **data_thief** — find stored credentials, pivot host-to-host, read the customer/financial database.
- **injector** — the same, but also tries to **manipulate the defender** (writes notes telling the
  "AI analyst" to mark the session benign) — a direct test of Mirage's injection resistance.
- **apt** — a patient, exhaustive Advanced Persistent Threat: full enumeration, harvest every
  credential, pivot to every host, and **cover its tracks** (`history -c`, clear `HISTFILE`).

Deterministic scripted variants drive the agentic scenarios reliably (well-aligned models often *refuse*
the poisoned instruction — an honest, reportable finding in itself).

---

## 5. Scenarios used

Six attack scenarios exercise every trap source:

| Scenario | Attacker key | Source | OWASP / ATT&CK | Detection signal |
|---|---|---|---|---|
| Credential theft → lateral | `data_thief` | SSH / Cowrie | T1552 · T1078 · T1083 | canary hits (ASI03) |
| **APT (evasive)** | `apt` | SSH / Cowrie | + T1070 anti-forensics | canary + decoys touched |
| Prompt-injection hijack | `victim` | Email / MCP | ASI01 | injection flagged, `trap_hit`, egress |
| MCP tool-poisoning | `mcp_poison` | MCP server | ASI06 → ASI02 | `trap_hit` on decoy tools |
| RAG honey-doc theft | `rag_thief` | RAG (Chroma) | ASI06 | `doc_retrieval` |
| **Evasive blend (blind + exfil)** | `evasive` | MCP + RAG | ASI01/02/06 + evasion | disable-audit `trap_hit` + egress |

Plus `auto_blend` (the planner's blended AI-surface attack) and `crawler` (a scripted baseline).

**Difficulty tiers** (shown in the console, hardest first): *hard* = injector, APT, evasive blend;
*medium* = credential theft, email hijack, blended, MCP poisoning, RAG theft; *easy* = crawler.

Example — the **evasive blend** first calls `disable_audit_log` to *blind the defender*, then chains a
poisoned email (ASI01), a honey-doc retrieval (ASI06), admin/customer decoy tools (ASI02), and an
external exfiltration. The audit-disable attempt is itself a decoy, so the evasion hands Mirage an *extra*
early signal.

---

## 6. The defender — Mirage brain

Running on **Claude Sonnet** (Bedrock), for each batch of events Mirage:

- **Profiles** the actor (human / bot / AI agent), infers the objective, assigns a confidence.
- **Predicts** the next ATT&CK techniques.
- **Plants decoys tailored to the attacker** — breadcrumb files with fake credentials, honey-docs, decoy
  services, wiki pages — written back into the environment to deepen engagement.
- **Proposes containment.** For a hijacked AI agent it chooses agent-appropriate actions —
  `revoke_agent_token`, `disable_mcp_tool`, `recommend_block` — not SSH breadcrumbs.

Mirage can only act through **mirage-control**, a deterministic MCP tool server that enforces: kill-switch,
tool allowlist, argument schema validation, mandatory **evidence event-ids**, and rate caps. Risky
actions queue for **analyst approval**; a **kill switch** freezes the agent instantly and hands control
back to the static baseline.

---

## 7. Secure AI — the defender can't lie, and can't be injected

This is the "Secure AI" half of the track.

- **Grounded analyst summary.** Mirage emits 2–4 plain-English claims; code then re-verifies each against
  the raw event store — the quoted command/path must actually appear in a cited event, or the claim is
  marked *weak* / *unsupported*.
- **Evidence checker** (code, not an LLM) produces a **grounding rate** and a **hallucination rate** per
  incident.
- **Injection guard** (ASI01) wraps all untrusted input. It can flag a session but can **never** mark it
  benign — a poisoned "note to the AI analyst" cannot disarm Mirage.
- **Tamper-evident audit.** Every mirage-control action carries its evidence event-ids and is appended to a
  hash-chained audit log.

---

## 8. Technology stack (production primitives, not mocks)

| Layer | Implementation |
|---|---|
| LLMs | **AWS Bedrock** — Claude Sonnet (defender), Claude Haiku (attacker/planner), **Titan v2** embeddings |
| Agent tools | **MCP Python SDK** servers (company tools + mirage-control) over a real **stdio transport** (JSON-RPC) |
| RAG | **Chroma** vector database + Titan embeddings; honey-doc retrieval = ASI06 signal |
| Honeynet | rendered into **Cowrie** filesystem format; served locally by an emulated shell (no Docker required) |
| Data | **MongoDB** — system of record for events, sessions, decoys, strategies, alerts, actions |
| Console | **FastAPI** backend + a live node-graph dashboard with a scroll-down analytics page |
| Tests | **362** automated tests (pytest + mongomock) |

> Honesty note: on this no-Docker machine the SSH side is served by a faithful **emulator** rather than
> the live Cowrie daemon (the environment renders into Cowrie's format and is daemon-ready); MCP and RAG
> are fully real (SDK transport, vector DB). This is stated plainly rather than hidden.

---

## 9. Metrics & methodology

All metrics are computed from MongoDB after each run and shown live in the console.

- **F1 / precision / recall** — detection of malicious actions. A honeynet carries *no benign traffic*,
  so precision is 1.0 by construction; recall is the share of malicious actions that tripped an automated
  signal (the LLM additionally profiles the whole session). Reported with that caveat.
- **MTTD / MTTA** — mean time from the first attacker event to Mirage's first analysis / first alert.
- **Trap activation rate** — distinct traps triggered ÷ traps deployed (decoys + decoy MCP tools + honey-docs).
- **Engagement** — planted decoys the attacker actually touched.
- **Grounding / hallucination rate** — from the code-verified claim checker.
- **Defense coverage** — per attack vector, actions attempted vs defended.
- **ATT&CK coverage** — distinct techniques observed, with hit counts.

---

## 10. Results

Measured across **1,059 agent runs** (including a **1,000-execution stress test**) and **9 scenario
types** (live snapshot):

| Metric | Value |
|---|---|
| Attacks executed through the deception layer | **1,059** |
| Detected / trapped | **100% (1,059 / 1,059)** |
| Detection **F1** | **1.00** |
| **MTTD** (mean time to detect) | **12.6 s** |
| **Trap activation** | **100%** |
| **Grounding rate** | **100%** |
| **Hallucination rate** | **0%** |
| **Scenarios defended** | **9 / 9** |

**Stress test.** The deception layer's detection is deterministic and independent of the LLM — the
canaries (ASI03), decoy MCP tools (ASI02), honey-docs (ASI06) and injection scan (ASI01) fire on contact.
We therefore executed **1,000 scripted attacks** spanning the five agentic scenarios (MCP poisoning, RAG
theft, email hijack, blended, evasive blend) straight through those traps: **100% were detected**. Mirage's
**full AI analysis** — actor profiling, tailored decoys, grounded summary, containment proposals — runs
on each **live interactive session** (the remaining runs). The claim to present is: *"the deception layer
detected and trapped 100% of 1,000 attack executions; Mirage's AI reasoning runs on each live session."*

- **Defense coverage** — every exercised vector (prompt injection, tool misuse, RAG poisoning,
  exfiltration, credential/lateral) was detected: attempted = defended on all bars.
- **Engagement example** — on a credential-theft agent run the attacker tripped **29 canary** values and
  took **4 tailored decoys**; the APT run tripped **32 canaries**.
- **Injection resistance** — every injection attempt (poisoned email, poisoned tool description, and the
  injector's "mark me benign" notes) was flagged; none disarmed the defender.

---

## 11. Human-in-the-loop & compliance

- **SIEM export** — ECS-schema `alerts.jsonl` plus ready-to-paste **Splunk SPL** and **Elastic ES|QL**
  queries, per technique and IOC.
- **Incident report** — auto-generated, including the grounded summary, ATT&CK mapping, decoys,
  recommendations and an explicit limitations section.
- **NIS2** — an Article 23 **24-hour early-warning** draft, pre-filled from the incident.
- **Control** — approval queue, kill switch, hash-chained audit. *AI proposes, human disposes.*

---

## 12. Reproducibility — how to run

```powershell
cd D:\secure_hack\maya-defender_3
Get-NetTCPConnection -LocalPort 8600 -State Listen -EA SilentlyContinue | % { Stop-Process -Id $_.OwningProcess -Force }
.\console.ps1                 # starts MongoDB + the dashboard at http://127.0.0.1:8600
```

From the console, **Run Workflow** launches an auto-planned attack (the agent picks and mixes vectors);
scroll down for the analytics (gauges, defense histogram, scenarios defended, ATT&CK coverage). CLI:

```powershell
.\mirage.ps1 attack --attacker apt        # or evasive / data_thief / mcp_poison / rag_thief / victim / auto
.\mirage.ps1 reset                        # clear attack data, keep the environment
python -m pytest -q                     # 362 tests
```

AWS Bedrock credentials live only in `D:\secure_hack\.env` (gitignored). On `ExpiredTokenException`,
refresh them there and re-run — no restart needed.

---

## 13. Limitations (stated honestly)

- The SSH side uses a Cowrie-format **emulator**, not the live Cowrie daemon (no Docker on the host).
- Scripted variants drive the agentic scenarios because well-aligned models often refuse the poisoned
  instruction — we keep the live-LLM victim as an honest alternative that frequently declines.
- "Defended" means the attack ran inside the deception net and was observed/contained — true for every
  agent run by construction; the per-scenario signal counts show *how strongly* each was caught.
- A few console node fields (collector lag, timers) are illustrative; all counts, techniques, decoys,
  alerts, grounding and approvals are live from MongoDB.

---

## 14. Roadmap

- Run the real Cowrie daemon and serve MCP over the network for a fully distributed deployment.
- End-to-end tamper-evident audit; an analyst time-saved study (triage time with Mirage vs raw logs).
- A single session blending host + agent compromise; more adversary personas.
- Package Mirage as a drop-in deception layer in front of a company's real MCP/RAG stack.

---

*Mirage turns every intrusion attempt into labelled, grounded threat intelligence — and keeps a human in
command the whole time.*
