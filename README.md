# Mirage

**An AI deception defense that turns a breach into an intelligence advantage.**

Mirage is an AI-driven honeynet. When an attacker gets in, they only ever touch a *fake* network. An AI defender agent (on AWS Bedrock) watches every move, profiles the intruder, plants tailored decoys to keep them engaged, and routes every consequential action through a human analyst. Across sessions it builds a memory of past incidents, so each new attack is handled faster than the last.

Built for the Secure Horizon hackathon — Track 2: *AI for Security & Secure AI*.

---

## The problem

- Attackers need only one way in; defenders have to cover everything.
- Real alerts drown in noise, so mean-time-to-detect is often measured in days.
- Once inside, an intruder moves laterally through **real** systems before anyone reacts.

Classic honeypots help, but they are static: a skilled attacker fingerprints and leaves. And the moment you put an LLM in the defensive loop, the LLM itself becomes an attack surface (prompt injection, tool misuse, memory poisoning).

Mirage addresses both: a honeynet that **adapts** via an AI agent, and an agent that is **hardened** against the techniques it defends against.

---

## What it does

1. **Trap** — a believable decoy environment (fake SSH shell, an MCP tool server, a RAG knowledge store) absorbs the intruder instead of real assets. Everything is seeded with canary tokens.
2. **Profile & deceive** — the defender agent reads the attacker's behavior live, maps it to MITRE ATT&CK, and plants decoys tailored to what they seem to be after.
3. **Human in control** — every consequential action is gated behind analyst approval, with a one-button kill switch.
4. **Learn** — a cross-session incident memory lets the agent recognize repeat techniques and reuse what worked before.

---

## Architecture

A live pipeline runs from intrusion to decision and loops back:

```
          ┌──────────────────────────── feedback: new decoys ◄─────────────────────┐
          ▼                                                                         │
  Attacker ──► Decoy environment ──► Collector ──► MongoDB ──► Mirage brain ──► Control ──► actions
             (SSH / MCP / RAG)      (ATT&CK map)  (event store) (Bedrock/Claude) (human approval)
```

- **Decoy environment** — emulated Cowrie SSH honeynet, a real **MCP (stdio)** tool server, and a real **RAG** store (Titan embeddings + Chroma) full of honey-documents.
- **Collector** — tails decoy logs, enriches each event, and maps actions to **MITRE ATT&CK** techniques, writing to the **MongoDB** event store.
- **Mirage brain** — the defender policy runs on **AWS Bedrock** (Claude Sonnet for strategy; a small model, Amazon Nova Micro, for the "watch it learn" demo). It decides actions and consults cross-session memory.
- **Control** — every action the brain proposes passes through `mirage-control`, which re-checks it, auto-runs safe actions, and queues the rest for a human. Includes the kill switch.
- **Dashboard** — a FastAPI "SOC console" that renders the whole pipeline live from MongoDB, plus run analytics and the learning curve.

### Repository layout

| Path | What's in it |
|------|--------------|
| `brain/` | The defender agent: policy, run loop, prompt, cross-session **memory**, and the **learning** engine. |
| `control/` | `MirageControl` — action gating, approval queue, kill switch, MCP server name `mirage-control`. |
| `collector/` | Log collector, event enrichment, and the ATT&CK technique mapping. |
| `ai_traps/` | Real MCP tool server/client (stdio) and the RAG store (Chroma / Titan). |
| `attackers/` | Attacker agents — an adversary-emulation `sweep` and LLM personas (data thief, injector, APT, red-team). |
| `honeynet/` | Cowrie-format SSH emulation and the wiki gateway. |
| `builder/` | Build mode: the agent designs the decoy environment (CLI / render / validate). |
| `defender/` | Defender service wiring. |
| `dashboard/` | FastAPI SOC console (`server.py`, `api.py`, `static/`) and a simpler Streamlit view (`app.py`). |
| `reliability/` | Reliability controls and kill-switch policy. |
| `canary/` | Canary-token filters and registry. |
| `integrations/` | SIEM export (ECS) and reports. |
| `eval/` | Evaluation matrix and analyst study. |
| `schemas/` | JSON schemas for actions, decoys, and events. |
| `local/run.py` | Local orchestrator and CLI entrypoint (`python -m local.run ...`). |
| `scripts/` | `demo_learning.py`, `many_events.py`, Mongo helper. |
| `tests/` | Test suite (366 tests, run against mongomock — no live DB needed). |
| `docs/` | Pitch deck generator and technical report. |

### Secure-AI measures (Track 2)

The agent is treated as a threat surface, mapped to OWASP Agentic Security (ASI):
- **Prompt injection (ASI01)** — attacker text is never executed as instructions.
- **Memory poisoning (ASI06)** — the incident memory stores **only defender-side facts**, never raw attacker input.
- **Runaway action** — human approval gate + kill switch; nothing irreversible happens unattended.

---

## Installation

### Prerequisites
- **Python 3.12**
- **MongoDB** running locally (default `mongodb://127.0.0.1:27017`)
- **AWS Bedrock** access in `us-west-2` — *optional*; only needed for the agent's LLM decisions and build mode. The test suite and the no-LLM event demo run without it.

### Setup (Windows / PowerShell)
```powershell
# 1. clone
git clone https://github.com/<you>/mirage.git
cd mirage

# 2. create the venv (the .ps1 helpers expect it at .venv312)
py -3.12 -m venv .venv312
.\.venv312\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. configure credentials (optional — only for Bedrock)
copy .env.example .env     # then fill in AWS values if you have them

# 4. make sure MongoDB is up (the helper script starts/verifies it)
powershell -ExecutionPolicy Bypass -File scripts\mongo.ps1
```

### Setup (macOS / Linux)
```bash
git clone https://github.com/<you>/mirage.git
cd mirage
python3.12 -m venv .venv312
source .venv312/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in AWS values if you have them
# ensure a local MongoDB is running on 127.0.0.1:27017
```

### Verify the install
```bash
PYTHONPATH=. python -m pytest -q      # expect: 366 passed
```

---

## Running it

The quickest path (Windows) — one command starts MongoDB and opens the dashboard:
```powershell
.\console.ps1          # SOC console at http://127.0.0.1:8600
```
Then click **Run Workflow** to launch an attack, and scroll to **"Mirage is learning"** → **▸ run learning demo**.

Other useful commands:
```powershell
.\mirage.ps1 setup                         # agent designs the decoy environment (needs Bedrock, first run)
.\mirage.ps1 attack --policy agent --seed 2  # one agent-defended attack (needs Bedrock)
.\mirage.ps1 reset                         # clear attack data (keeps environment + learning history)
```
No-Bedrock paths (deterministic traps + ATT&CK mapping):
```bash
PYTHONPATH=. python scripts/many_events.py 1000   # populate the event store with 1000+ events across sessions
```

---

## Known limitations

- **Bedrock required for the AI brain.** The adaptive defense, build mode, and the learning demo need AWS Bedrock access in `us-west-2`. Without credentials you can still run the full test suite and the deterministic no-LLM event demo, but the agent won't make live decisions.
- **The SSH honeynet is emulated**, not a full Cowrie container. It is Cowrie-*format* (so logs and ATT&CK mapping are realistic) but runs in-process for portability; the MCP tool server and RAG store, by contrast, are real.
- **Runtime data isn't committed.** `data/` (the agent-built environment, decoy logs, trap logs, RAG index) is generated at run time and git-ignored, so a fresh clone starts with no environment — run `.\mirage.ps1 setup` (Bedrock) to build one.
- **Single-node / local by default.** MongoDB and the services run locally; the Docker Compose setup (`docker-compose.yml`) is intended for an EC2 deployment and isn't exercised by the local flow.
- **The "learning" signal is memory- and coverage-driven, not error-correction.** We use a deliberately small model (Nova Micro) so growth is visible; the measurable gains are rising knowledge coverage and reuse of past cases, not a model that stops hallucinating.
- **Scope is a demonstrator.** This is a hackathon prototype focused on showing the deception loop and secure-AI controls end to end, not a production-hardened IDS.

---

## License

Prototype built for the Secure Horizon hackathon. No warranty.
