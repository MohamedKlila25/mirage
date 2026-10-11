"""What the defender is allowed to do on its own, and when a human must decide.

Two autonomy levels:
  - honeynet (everything there is fake): allowlisted tools with validated params run
    automatically, but only when the session's verified confidence is high enough.
  - production / AI agents: never automatic. Always a proposal for the analyst.

Plus a kill switch checked before every decision, and a never-block list the defender
can never propose to block (your own infrastructure, cloud ranges, partners).
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

BREADCRUMB_TYPES = {"fake_credentials", "fake_db_dump", "fake_ssh_key", "fake_env_file", "fake_wiki_page"}


@dataclass
class PolicyConfig:
    confidence_threshold: float = 0.6
    decoy_hosts: set[str] = field(default_factory=lambda: {"fake-jump-01", "fake-db-01", "fake-ftp-01"})
    never_block: list[str] = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",   # internal ranges
        "amazonaws.com", "github.com",                                    # infra we depend on
    ])
    known_techniques: set[str] = field(default_factory=set)              # from approved memory
    kill_switch_env: str = "MIRAGE_KILL_SWITCH"
    kill_switch_file: str = "/tmp/mirage_kill_switch"

    def kill_switch_on(self) -> bool:
        return os.environ.get(self.kill_switch_env, "") == "1" or Path(self.kill_switch_file).exists()


def _validate_honeynet_params(tool: str, params: dict, session_id: str, cfg: PolicyConfig) -> list[str]:
    errs = []
    if tool == "plant_breadcrumb":
        if params.get("type") not in BREADCRUMB_TYPES:
            errs.append(f"breadcrumb type must be one of {sorted(BREADCRUMB_TYPES)}")
        if params.get("host") not in cfg.decoy_hosts:
            errs.append("host is not a decoy")
        if set(params) - {"type", "host"}:
            errs.append(f"unexpected params {sorted(set(params) - {'type', 'host'})}")
    elif tool == "slow_session":
        if params.get("session_id") != session_id:
            errs.append("can only act on the current session")
        d = params.get("delay_ms")
        if not isinstance(d, int) or not 0 < d <= 10_000:
            errs.append("delay_ms must be an int in 1..10000")
    elif tool == "kill_session":
        if params.get("session_id") != session_id:
            errs.append("can only act on the current session")
    elif tool == "reset_decoy":
        if params.get("host") not in cfg.decoy_hosts:
            errs.append("host is not a decoy")
    return errs


HONEYNET_TOOLS = {"plant_breadcrumb", "slow_session", "kill_session", "reset_decoy"}


def check_honeynet_action(tool: str, params: dict, session_id: str, cfg: PolicyConfig) -> tuple[str, list[str]]:
    """-> (decision, reasons). decision in: auto | rejected"""
    if tool not in HONEYNET_TOOLS:
        return "rejected", [f"tool '{tool}' is not on the honeynet allowlist"]
    errs = _validate_honeynet_params(tool, params, session_id, cfg)
    return ("rejected", errs) if errs else ("auto", [])


def _is_never_block(ioc: str, cfg: PolicyConfig) -> bool:
    ioc = ioc.strip().lower()
    try:
        ip = ipaddress.ip_address(ioc)
        for entry in cfg.never_block:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        pass
    return any(ioc == d or ioc.endswith("." + d) for d in cfg.never_block if not re.match(r"^[\d./:]+$", d))


def check_proposal_payload(ptype: str, payload: dict, cfg: PolicyConfig) -> list[str]:
    """Hard rejections that no human approval should even be asked for."""
    errs = []
    if ptype == "ioc_block":
        ioc = str(payload.get("ioc", ""))
        if not ioc:
            errs.append("ioc_block without an ioc")
        elif _is_never_block(ioc, cfg):
            errs.append(f"{ioc} is on the never-block list")
    elif ptype == "sigma_rule" and not payload.get("yaml"):
        errs.append("sigma_rule without yaml")
    elif ptype == "disable_tool" and not payload.get("tool_name"):
        errs.append("disable_tool without tool_name")
    elif ptype == "revoke_token" and not payload.get("agent_id"):
        errs.append("revoke_token without agent_id")
    elif ptype == "quarantine_doc" and not payload.get("doc_id"):
        errs.append("quarantine_doc without doc_id")
    return errs
