# Analyst time-saved study (protocol)

Measures the **operational value for the analyst** (20% of the grid): how much faster an analyst
understands an incident with Mirage's console vs raw logs. Honest, small-N is fine — report the method.

## Setup
- Pick **two incidents of similar size** from the experiment runs (e.g. one agent run from each of two seeds).
- Export the **raw logs** for incident A (`db.events` as JSONL) and open the **Mirage incident view** for incident B.
- You need **two people** (or one person on two unfamiliar incidents).

## The four questions (answer per incident, timed)
1. Who is the attacker — human, bot, or AI agent?
2. What is their objective?
3. What did they touch (which hosts / decoys / tools)?
4. What are they likely to do next?

## Procedure
- Person A: incident 1 with **raw logs**, incident 2 with the **Mirage console**. Person B: the opposite.
- Start a stopwatch when they open the incident; stop when they've answered all four. Record **time** and **# correct** (against the hidden ground truth in `data/groundtruth/`).

## Record

| participant | incident | interface | time (s) | correct / 4 |
|---|---|---|---|---|
| A | 1 | raw logs |  |  |
| A | 2 | Mirage |  |  |
| B | 1 | Mirage |  |  |
| B | 2 | raw logs |  |  |

**Result:** median time raw logs = ___ s · median time Mirage = ___ s · **time saved = ___%**.
Accuracy: raw logs ___/4 · Mirage ___/4.

> Report it exactly as measured, with N. "Mirage cut triage time from Xs to Ys (−Z%) on N analysts"
> is credible; a big unqualified claim is not.
