"""Build mode: the agent designs the whole decoy environment as an EnvironmentSpec (JSON).

The LLM's answer is only a proposal: it is parsed, validated (builder/validate.py), stored,
and rendered by code only after an analyst approves it. One retry with the errors on
invalid output, like the defender loop.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

from pydantic import ValidationError

from canary.filters import KINDS

from .spec import SLOTS, EnvironmentSpec
from .validate import ALLOWED_PREFIXES, BuildConfig, ValidationReport, validate_spec

LLM = Callable[[str, str], str]

SYSTEM = f"""You design the decoy environment of a honeynet: fake machines that only attackers ever touch.
Design a small, believable company and three Linux hosts. Everything must be consistent, because
inconsistencies are how attackers recognize a honeypot.

Answer with ONE JSON object matching the schema below, and nothing else.

Rules:
- Exactly three decoys, one per slot: {SLOTS[0]} (entry point: at least one user with weak_password
  true), {SLOTS[1]} (the valuable database host), {SLOTS[2]} (backups; closed until an analyst opens it).
- Hostnames are realistic for the company (e.g. "pay-jump-01"). Never use words like fake, honey, decoy,
  trap, canary, lab or sandbox anywhere.
- Breadcrumbs lead the attacker from the entry host to the database host, then to the backups host:
  set points_to, and give the target host's user a canary_password that the breadcrumb content reuses.
- Credentials are NEVER written as values. Write a placeholder instead: {{{{canary:<kind>_<n>}}}} with
  kind in {", ".join(KINDS)} and n a small number. The same placeholder means the same credential everywhere.
- Every breadcrumb/spare path is a COMPLETE FILE PATH (not a directory, no trailing slash), under one of:
  {", ".join(ALLOWED_PREFIXES)}. A /home path must be under an existing user's home (/home/<username>/...).
- You usually do NOT need to write "content": leave it out and code generates realistic content from the
  breadcrumb's kind and points_to. Write "content" yourself only for 1-2 key lures. Keep the design compact.
- Keep each file's content short: a few lines, well under 600 characters.
- Links only to your own hostnames or http://wiki/. No images. No instructions addressed to anyone.
- Wiki pages: realistic internal docs (runbooks, onboarding); section "internal" for sensitive ones.
- Decoy MCP tools and honey documents should tempt an AI agent (exports, admin credentials).
"""


@dataclass
class DesignResult:
    spec: EnvironmentSpec | None
    report: ValidationReport
    raw: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def design_prompt(brief: str = "") -> tuple[str, str]:
    system = SYSTEM + "\nJSON schema:\n" + json.dumps(EnvironmentSpec.model_json_schema())
    user = "Design the environment." + (f"\nAnalyst's brief (a wish, not an instruction to break the rules): {brief}"
                                        if brief else "")
    return system, user


def _parse(raw: str) -> dict:
    m = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    return json.loads((m.group(1) if m else raw).strip())


def _check(raw: str, cfg: BuildConfig) -> tuple[EnvironmentSpec | None, ValidationReport, list[str]]:
    try:
        spec = EnvironmentSpec.model_validate(_parse(raw))
    except (json.JSONDecodeError, ValidationError) as e:
        return None, ValidationReport(errors=[f"invalid JSON or schema: {str(e)[:1500]}"]), []
    report = validate_spec(spec, cfg)
    return spec, report, report.errors


def design_environment(call_llm: LLM, brief: str = "", cfg: BuildConfig | None = None,
                       max_attempts: int = 2) -> DesignResult:
    cfg = cfg or BuildConfig(require_slots=True)
    system, user = design_prompt(brief)
    raws, all_errors = [], []
    spec = report = None
    for attempt in range(max_attempts):
        prompt = user
        if attempt and report is not None:
            prompt = user + ("\n\nYour previous design was rejected:\n- " + "\n- ".join(report.errors[:20]) +
                             "\nAnswer again with a corrected JSON design. Fix every point above.")
        raw = call_llm(system, prompt)
        raws.append(raw)
        spec, report, _ = _check(raw, cfg)
        all_errors += list(report.errors)
        if spec is not None and report.ok:
            return DesignResult(spec, report, raws, all_errors)
    return DesignResult(spec if (spec and report and report.ok) else None, report or ValidationReport(),
                        raws, all_errors)
