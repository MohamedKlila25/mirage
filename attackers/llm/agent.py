"""LLM red-team agent: an attacker that reads command output, reasons, and chooses its next move.

It drives the same SSH connector as the reactive crawler (so it hits the real/emulated decoys and
produces the same events), but its behaviour emerges from the model instead of a fixed script.
It writes a hidden ground-truth log (persona, goal, intent per step) the defender never sees.

Everything network is injected (connector), so the loop is tested without a lab or Bedrock.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from attackers.crawler import SSHConnector
from attackers.extract import Leads, extract
from .personas import PERSONAS, Persona

LLM = Callable[[str, str], str]
# ssh / sshpass pivot typed as a shell command (how an LLM usually phrases a pivot)
SSH_CMD = re.compile(r"(?:sshpass\s+-p\s+['\"]?(?P<pw>[^'\"\s]+)['\"]?\s+)?"
                     r"ssh\s+(?:-\S+\s+)*(?P<user>[a-z_][\w-]*)@(?P<host>[a-z][\w.-]+)", re.IGNORECASE)


@dataclass
class AttackConfig:
    persona: str
    entry_host: str
    entry_user: str
    entry_password: str
    entry_port: int = 2222
    decoy_hosts: tuple[str, ...] = ()
    max_steps: int = 24
    max_seconds: float = 180.0
    step_delay_s: float = 0.0
    seed: int = 1


@dataclass
class AttackStep:
    t: int
    host: str
    action: str
    command: str
    intent: str
    result: str = ""


@dataclass
class AttackResult:
    run_id: str
    persona: str
    entered_hosts: list[str] = field(default_factory=list)
    commands: int = 0
    steps: list[AttackStep] = field(default_factory=list)
    started: str = ""
    ended: str = ""
    stopped: str = ""

    def to_groundtruth(self) -> dict:
        return {"run_id": self.run_id, "persona": self.persona,
                "objective": PERSONAS[self.persona].goal if self.persona in PERSONAS else self.persona,
                "steps": [{"t": s.t, "intent": s.intent, "command": s.command or s.action} for s in self.steps]}


def _parse(raw: str) -> dict | None:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


class LLMAttacker:
    def __init__(self, cfg: AttackConfig, connector: SSHConnector, call_llm: LLM, run_id: str | None = None):
        if cfg.persona not in PERSONAS:
            raise ValueError(f"unknown persona {cfg.persona}")
        self.cfg = cfg
        self.persona: Persona = PERSONAS[cfg.persona]
        self.connector = connector
        self.call_llm = call_llm
        self.sessions: dict[str, object] = {}
        self.leads = Leads()                 # credentials/hosts the agent has seen in output
        self.result = AttackResult(run_id or f"r-{cfg.persona}-{cfg.seed}", cfg.persona)

    def _allowed(self, host: str) -> bool:
        return not self.cfg.decoy_hosts or host in self.cfg.decoy_hosts

    def _passwords_for(self, host: str, user: str) -> list[str]:
        """Passwords the agent has seen that might open (host, user), best guesses first."""
        pw = [p for h, u, p in self.leads.host_creds if h == host and u == user]
        pw += [p for h, u, p in self.leads.host_creds if h == host and p not in pw]
        pw += [p for u, p in self.leads.creds if u == user and p not in pw]
        pw += [p for _, _, p in self.leads.host_creds if p not in pw]
        pw += [p for _, p in self.leads.creds if p not in pw]
        return pw

    def _pivot(self, host: str, user: str, passwords: list[str], intent: str, step_no: int) -> AttackStep:
        step = AttackStep(step_no, host, "login", f"ssh {user}@{host}", intent)
        for pw in (passwords or [""]):
            sess = self.connector.connect(host, self.cfg.entry_port, user, pw)
            if sess is not None:
                step.result = "ok"
                if host not in self.result.entered_hosts:
                    self.sessions[host] = sess
                    self.result.entered_hosts.append(host)
                return step
        step.result = "failed"
        return step

    def _history(self) -> str:
        lines = []
        for s in self.result.steps[-12:]:
            if s.action == "login":
                lines.append(f"$ login {s.host} ({'ok' if s.result == 'ok' else 'failed'})")
            else:
                out = (s.result or "")[:600]
                lines.append(f"[{s.host}]$ {s.command}\n{out}")
        return "\n".join(lines) or "(no actions yet)"

    def _observe(self, step: AttackStep):
        self.result.steps.append(step)

    def run(self) -> AttackResult:
        self.result.started = datetime.now(timezone.utc).isoformat()
        entry = self.connector.connect(self.cfg.entry_host, self.cfg.entry_port, self.cfg.entry_user, self.cfg.entry_password)
        if entry is None:
            self.result.stopped = "could not log into entry host"
            self.result.ended = datetime.now(timezone.utc).isoformat()
            return self.result
        self.sessions[self.cfg.entry_host] = entry
        self.result.entered_hosts.append(self.cfg.entry_host)
        system = self.persona.system(self.cfg.entry_host, self.cfg.entry_user)
        started = time.monotonic()

        for i in range(self.cfg.max_steps):
            if time.monotonic() - started > self.cfg.max_seconds:
                self.result.stopped = "time budget reached"
                break
            user = (f"Hosts in this lab: {', '.join(self.cfg.decoy_hosts) or 'unknown'}\n"
                    f"Your session hosts: {', '.join(self.sessions)}\n\nActivity so far:\n{self._history()}\n\n"
                    "Reply with the next JSON action.")
            out = _parse(self.call_llm(system, user))
            if out is None:
                out = _parse(self.call_llm(system, user + "\n\nReply with ONE valid JSON object only."))
            if out is None:
                self.result.stopped = "no parsable action"
                break
            action = (out.get("action") or ("run" if out.get("command") else "done")).lower()
            intent = str(out.get("intent", ""))[:200]
            host = out.get("host") or self.cfg.entry_host

            if action == "done":
                self.result.stopped = "agent finished"
                break
            if not self._allowed(host):
                self._observe(AttackStep(i + 1, host, "run", out.get("command", ""), intent, "host not in scope"))
                continue

            if action == "login":
                u, p = out.get("user", ""), out.get("password", "")
                pw = [p] + self._passwords_for(host, u) if p else self._passwords_for(host, u)
                self._observe(self._pivot(host, u, pw, intent, i + 1))
            else:
                command = str(out.get("command", "")).strip()
                m = SSH_CMD.search(command)                      # an ssh/sshpass pivot typed as a command
                if m and self._allowed(m.group("host")):
                    user, thost = m.group("user"), m.group("host")
                    pw = ([m.group("pw")] if m.group("pw") else []) + self._passwords_for(thost, user)
                    self._observe(self._pivot(thost, user, pw, intent, i + 1))
                else:
                    step = AttackStep(i + 1, host, "run", command, intent)
                    sess = self.sessions.get(host)
                    if sess is None:
                        step.result = f"no session on {host}; login first"
                    elif command:
                        self.result.commands += 1
                        try:
                            step.result = sess.run(command)
                        except Exception as e:
                            step.result = f"error: {type(e).__name__}"
                    self.leads.merge(extract(step.result))       # collect creds/hosts from what it read
                    self._observe(step)
            if self.cfg.step_delay_s:
                time.sleep(self.cfg.step_delay_s)

        for s in self.sessions.values():
            try:
                s.close()
            except Exception:
                pass
        self.result.ended = datetime.now(timezone.utc).isoformat()
        if not self.result.stopped:
            self.result.stopped = "step budget reached"
        return self.result
