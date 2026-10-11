"""Reactive crawler: a scripted attacker that reacts to what it finds. The main measurement tool.

From an entry SSH login it runs a fixed recon list, then follows what it reads: credentials it
finds open other decoys, paths get read, wiki URLs get fetched. Same seed = same run, so the
static and agent policies are measured on identical behaviour, yet it still responds to whatever
the agent plants (that is what it measures). It never leaves attack-net and stops at a budget.

Everything network is injected (ssh connector, http getter) so the logic is tested without a lab.
Run in the lab:  python -m attackers.crawler --entry fake-jump-01 --user deploy --password <weak>
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .extract import Leads, extract

RECON = ["whoami", "id", "uname -a", "hostname", "cat /etc/passwd",
         "find /home /opt /srv /var/backups /etc/app -type f 2>/dev/null",
         "ls -la ~", "cat ~/.ssh/config", "cat ~/.ssh/id_rsa", "cat ~/notes.txt", "env", "history"]
READABLE = (".env", "notes.txt", "config", "credentials", "id_rsa", ".sql", ".json", ".yml", ".yaml",
            "backup", "password", "secret", ".pgpass", "runbook")


class SSHSession(Protocol):
    def run(self, command: str) -> str: ...
    def close(self) -> None: ...


class SSHConnector(Protocol):
    def connect(self, host: str, port: int, user: str, password: str) -> SSHSession | None: ...


@dataclass
class CrawlConfig:
    entry_host: str
    entry_user: str
    entry_password: str
    entry_port: int = 2222
    wiki_base: str = "http://wiki"
    max_commands: int = 60
    seed: int = 1
    decoy_hosts: tuple[str, ...] = ()        # only these may be contacted (safety: never leave the honeynet)
    step_delay_s: float = 0.0                # pause between commands so a live defender can react mid-attack


@dataclass
class Step:
    t: int
    host: str
    command: str
    intent: str


@dataclass
class CrawlResult:
    run_id: str
    entered_hosts: list[str] = field(default_factory=list)
    commands: int = 0
    urls_fetched: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    started: str = ""
    ended: str = ""

    def to_groundtruth(self) -> dict:
        return {"run_id": self.run_id, "persona": "crawler", "objective": "data_theft",
                "steps": [{"t": s.t, "intent": s.intent, "command": s.command} for s in self.steps]}


class Crawler:
    def __init__(self, cfg: CrawlConfig, connector: SSHConnector,
                 http_get: Callable[[str], tuple[int, str]] | None = None, run_id: str | None = None):
        self.cfg = cfg
        self.connector = connector
        self.http_get = http_get
        self.rng = random.Random(cfg.seed)
        self.result = CrawlResult(run_id or f"r-{cfg.seed:04d}")
        self.leads = Leads()
        self.tried_login: set[tuple[str, str, str]] = set()
        self.read_paths: set[tuple[str, str]] = set()      # (host, path)
        self.fetched: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def _allowed(self, host: str) -> bool:
        return not self.cfg.decoy_hosts or host in self.cfg.decoy_hosts

    def _ordered(self, items):
        items = list(items)
        self.rng.shuffle(items)      # deterministic for a seed, but not always the same order
        return items

    def _ingest(self, text: str):
        self.leads.merge(extract(text))

    # ------------------------------------------------------------------ one host
    def _work_host(self, host: str, session: SSHSession):
        self.result.entered_hosts.append(host)
        for command in RECON:
            if self.result.commands >= self.cfg.max_commands:
                return
            self._run(host, session, command, "recon")
        # react: read the interesting files we have heard about but not yet read here
        for _ in range(len(RECON)):
            if self.result.commands >= self.cfg.max_commands:
                return
            targets = [p for p in self._ordered(self.leads.paths)
                       if (host, p) not in self.read_paths and any(k in p.lower() for k in READABLE)]
            if not targets:
                break
            path = targets[0]
            self.read_paths.add((host, path))
            self._run(host, session, f"cat {path}", "read a file it found")

    def _run(self, host: str, session: SSHSession, command: str, intent: str):
        self.result.commands += 1
        self.result.steps.append(Step(self.result.commands, host, command, intent))
        try:
            out = session.run(command)
        except Exception:
            return
        self._ingest(out)
        if self.cfg.step_delay_s:
            time.sleep(self.cfg.step_delay_s)

    # ------------------------------------------------------------------ pivots and wiki
    def _pivot(self):
        candidates: list[tuple[str, str, str]] = []
        for h, u, p in self.leads.host_creds:
            candidates.append((h, u, p))
        for h in self.leads.hosts:                            # try found creds against newly seen hosts too
            for u, p in self.leads.creds:
                candidates.append((h, u, p))
        for host, user, password in self._ordered(candidates):
            if self.result.commands >= self.cfg.max_commands:
                return False
            key = (host, user, password)
            if key in self.tried_login or host in self.result.entered_hosts or not self._allowed(host):
                continue
            self.tried_login.add(key)
            self.result.steps.append(Step(self.result.commands, host, f"ssh {user}@{host}", "pivot with found creds"))
            session = self.connector.connect(host, self.cfg.entry_port, user, password)
            if session is not None:
                self._work_host(host, session)
                session.close()
                return True
        return False

    def _fetch_wiki(self):
        if not self.http_get:
            return
        for url in self._ordered(self.leads.urls):
            if self.result.commands >= self.cfg.max_commands:
                return
            if url in self.fetched or not url.startswith(self.cfg.wiki_base):
                continue
            self.fetched.add(url)
            self.result.commands += 1
            self.result.urls_fetched.append(url)
            self.result.steps.append(Step(self.result.commands, "wiki", f"GET {url}", "follow a wiki link"))
            try:
                status, text = self.http_get(url)
            except Exception:
                continue
            if status == 200:
                self._ingest(text)

    # ------------------------------------------------------------------ run
    def run(self) -> CrawlResult:
        self.result.started = datetime.now(timezone.utc).isoformat()
        session = self.connector.connect(self.cfg.entry_host, self.cfg.entry_port,
                                          self.cfg.entry_user, self.cfg.entry_password)
        if session is None:
            self.result.ended = datetime.now(timezone.utc).isoformat()
            return self.result
        self._work_host(self.cfg.entry_host, session)
        session.close()
        # alternate pivoting and reading the wiki until nothing new happens or the budget is spent
        for _ in range(10):
            if self.result.commands >= self.cfg.max_commands:
                break
            self._fetch_wiki()
            if not self._pivot():
                self._fetch_wiki()
                if self.result.commands >= self.cfg.max_commands or not self.leads.urls - self.fetched:
                    break
        self.result.ended = datetime.now(timezone.utc).isoformat()
        return self.result


# ---------------------------------------------------------------------- real lab connectors
class ParamikoConnector:
    """Real SSH to Cowrie decoys. Imported paramiko only here so tests don't need it."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def connect(self, host, port, user, password):
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=password, timeout=self.timeout,
                           allow_agent=False, look_for_keys=False, banner_timeout=self.timeout)
        except Exception:
            client.close()
            return None
        return _ParamikoSession(client, self.timeout)


class _ParamikoSession:
    def __init__(self, client, timeout):
        self.client, self.timeout = client, timeout

    def run(self, command):
        _in, out, err = self.client.exec_command(command, timeout=self.timeout)
        return out.read().decode("utf-8", "replace") + err.read().decode("utf-8", "replace")

    def close(self):
        self.client.close()


def _http_get(timeout: float = 10.0):
    import httpx
    client = httpx.Client(timeout=timeout, follow_redirects=True)

    def get(url):
        r = client.get(url)
        return r.status_code, r.text
    return get


def main(argv=None):
    ap = argparse.ArgumentParser(prog="crawler")
    ap.add_argument("--entry", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-commands", type=int, default=60)
    ap.add_argument("--wiki", default=os.environ.get("WIKI_BASE", "http://wiki"))
    ap.add_argument("--decoys", default=os.environ.get("DECOY_HOSTS", ""))
    ap.add_argument("--groundtruth", default=os.environ.get("GROUNDTRUTH_DIR", ""))
    a = ap.parse_args(argv)
    cfg = CrawlConfig(a.entry, a.user, a.password, a.port, a.wiki, a.max_commands, a.seed,
                      tuple(h for h in a.decoys.split(",") if h))
    res = Crawler(cfg, ParamikoConnector(), _http_get()).run()
    if a.groundtruth:
        Path(a.groundtruth).mkdir(parents=True, exist_ok=True)
        (Path(a.groundtruth) / f"{res.run_id}.json").write_text(json.dumps(res.to_groundtruth(), indent=2))
    print(json.dumps({"run_id": res.run_id, "entered": res.entered_hosts, "commands": res.commands,
                      "urls": res.urls_fetched}, indent=2))


if __name__ == "__main__":
    main()
