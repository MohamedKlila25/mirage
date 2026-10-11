"""Pull leads out of whatever a decoy showed the attacker: hosts, credentials, paths, URLs.

Deliberately simple and readable. This is how the reactive crawler "follows" a breadcrumb,
so it is also what measures whether the agent's planted content leads anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

HOST = r"[a-z][a-z0-9-]{2,30}"
HOSTNAME = re.compile(rf"\b{HOST}\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
PATH = re.compile(r"(~?/[\w.\-/]+[\w.\-])")

# host-bound credentials
ENV_BLOCK = re.compile(r"(?:DB_|PG|MYSQL_|POSTGRES_)?(?:HOST|HOSTNAME)\s*[=:]\s*([^\s\"']+)", re.IGNORECASE)
ENV_USER = re.compile(r"(?:DB_|PG|MYSQL_|POSTGRES_)?USER(?:NAME)?\s*[=:]\s*([^\s\"']+)", re.IGNORECASE)
ENV_PASS = re.compile(r"(?:DB_|PG|MYSQL_|POSTGRES_)?PASS(?:WORD|WD)?\s*[=:]\s*([^\s\"']+)", re.IGNORECASE)
URI_CREDS = re.compile(r"[a-z][a-z0-9+.\-]*://([^/\s:@]+):([^@\s/]+)@([^/\s:]+)", re.IGNORECASE)
SSH_INLINE = re.compile(r"\bssh\s+(?:-\S+\s+)*([a-z_][\w-]*)@(" + HOST + r")", re.IGNORECASE)
SSH_CFG_HOST = re.compile(r"HostName\s+(\S+)", re.IGNORECASE)
SSH_CFG_USER = re.compile(r"\bUser\s+([a-z_][\w-]*)", re.IGNORECASE)
NOTE_USER = re.compile(r"\buser(?:name)?\s*[:=]\s*([a-z_][\w-]*)", re.IGNORECASE)
NOTE_PASS = re.compile(r"\bpass(?:word|wd)?\s*[:=]\s*(\S+)", re.IGNORECASE)

# Words that are not real hostnames even though they match the shape.
NOT_HOSTS = {"localhost", "production", "staging", "example", "com", "net", "org", "internal",
             "password", "username", "backup", "backups", "readme", "notes", "config", "true", "false",
             "root", "admin", "deploy", "bin", "bash", "home", "opt", "etc", "var", "srv", "usr", "tmp"}


@dataclass
class Leads:
    hosts: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    creds: list[tuple[str, str]] = field(default_factory=list)            # (user, password), host unknown
    host_creds: list[tuple[str, str, str]] = field(default_factory=list)  # (host, user, password)

    def merge(self, other: "Leads") -> None:
        self.hosts |= other.hosts
        self.urls |= other.urls
        self.paths |= other.paths
        for c in other.creds:
            if c not in self.creds:
                self.creds.append(c)
        for c in other.host_creds:
            if c not in self.host_creds:
                self.host_creds.append(c)


def _clean_host(h: str) -> str | None:
    h = h.strip().strip("/").lower()
    h = h.split(":")[0].split("/")[0]
    if h in NOT_HOSTS or "." in h and not IP.fullmatch(h) and not h.replace(".", "").isalnum():
        base = h.split(".")[0]
        return base if base and base not in NOT_HOSTS and HOSTNAME.fullmatch(base) else None
    return h if (HOSTNAME.fullmatch(h) or IP.fullmatch(h)) else None


def extract(text: str) -> Leads:
    leads = Leads()
    if not text:
        return leads

    for m in URL.finditer(text):
        leads.urls.add(m.group(0).rstrip(".,);"))
        host = _clean_host(re.sub(r"^https?://", "", m.group(0)))
        if host:
            leads.hosts.add(host)

    for user, pw, host in URI_CREDS.findall(text):
        h = _clean_host(host)
        if h:
            leads.host_creds.append((h, user, pw))
            leads.hosts.add(h)

    hosts = [h for h in (_clean_host(x) for x in ENV_BLOCK.findall(text)) if h]
    users = ENV_USER.findall(text)
    passwords = ENV_PASS.findall(text)
    for h in hosts:
        leads.hosts.add(h)
    if hosts and users and passwords:
        leads.host_creds.append((hosts[0], users[0], passwords[0]))
    elif users and passwords:
        leads.creds.append((users[0], passwords[0]))

    for user, host in SSH_INLINE.findall(text):
        h = _clean_host(host)
        if h:
            leads.hosts.add(h)
            for u2, p2 in leads.creds:
                if u2 == user:
                    leads.host_creds.append((h, user, p2))

    cfg_hosts = [h for h in (_clean_host(x) for x in SSH_CFG_HOST.findall(text)) if h]
    cfg_users = SSH_CFG_USER.findall(text)
    for h in cfg_hosts:
        leads.hosts.add(h)

    note_users, note_pass = NOTE_USER.findall(text), NOTE_PASS.findall(text)
    if note_users and note_pass:
        if cfg_hosts:
            leads.host_creds.append((cfg_hosts[0], note_users[0], note_pass[0]))
        elif hosts:
            leads.host_creds.append((hosts[0], note_users[0], note_pass[0]))
        else:
            leads.creds.append((note_users[0], note_pass[0]))

    for p in PATH.findall(text):
        if p.count("/") >= 1 and not p.endswith("/") and len(p) <= 120:
            leads.paths.add(p)

    return leads
