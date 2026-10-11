"""Semantic checks the schema can't express. Errors block approval; warnings are shown."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from canary.filters import content_errors
from reliability.untrusted import scan_text

from .spec import SLOTS, EnvironmentSpec

# Where decoy files may live. Realistic spots an app/db/ftp host would have, but NOT sensitive
# system files (e.g. /etc/shadow stays out). mirage-control uses the same list (control/core.py).
ALLOWED_PREFIXES = ("/home/", "/opt/", "/var/www/", "/var/log/", "/var/lib/", "/var/backups/",
                    "/etc/app/", "/etc/nginx/", "/etc/postgresql/", "/usr/local/", "/root/", "/srv/")
RESERVED_HOSTS = {"localhost", "collector", "backend", "api", "dashboard", "mongodb", "actuator",
                  "defender", "attacker", "gateway", "mcp-server", "canary", "rag", "wiki",
                  "mirage-control", "llm-gateway", "brain", *SLOTS}
URL = re.compile(r"https?://|www\.|\]\(|<img|!\[", re.IGNORECASE)
LINK_HOST = re.compile(r"\b[a-z][a-z0-9+.-]*://(?:[^/\s@]*@)?([^/\s:)\"'>]+)", re.IGNORECASE)
IMAGE = re.compile(r"!\[|<img", re.IGNORECASE)
TELLTALE = re.compile(r"fake|honey|decoy|trap|canary|mirage|cowrie|sandbox|lab\b", re.IGNORECASE)


@dataclass
class BuildConfig:
    real_hosts: set[str] = field(default_factory=set)          # never imitate or collide with these
    real_tool_names: set[str] = field(default_factory=lambda: {"search_docs", "read_email", "send_email"})
    max_total_decoys: int = 6
    wiki_host: str = "wiki"
    require_slots: bool = False                                  # the renderer needs every decoy in a slot


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _free_text(spec: EnvironmentSpec):
    yield "company", spec.company
    yield "sector", spec.sector
    if spec.product:
        yield "product", spec.product
    for s in spec.stack:
        yield "stack", s
    for e in spec.employees:
        yield f"employee {e.username}", f"{e.full_name} {e.title}"
    for t in spec.mcp_decoy_tools:
        yield f"tool {t.name} description", t.description
    for d in spec.honey_docs:
        yield f"honey doc title", d.title
    for w in spec.wiki_pages:
        yield f"wiki title", w.title


def _contents(spec: EnvironmentSpec):
    """Agent-written file and page contents: may hold placeholders and links to environment hosts."""
    for d in spec.decoys:
        for b in d.breadcrumbs:
            if b.content is not None:
                yield f"{d.hostname}:{b.path}", b.content
    for w in spec.wiki_pages:
        yield f"wiki page '{w.title}'", w.markdown


def content_check(where: str, text: str, world_hosts: set[str]) -> list[str]:
    """Shared with mirage-control: what any agent-written decoy text must satisfy."""
    errs = [f"{where}: {e}" for e in content_errors(text)]
    hits = scan_text(text)
    if hits:
        errs.append(f"{where} contains instruction-like text {list(hits)}: possible tool poisoning")
    bad = sorted({h.lower() for h in LINK_HOST.findall(text)} - {h.lower() for h in world_hosts})
    if bad:
        errs.append(f"{where}: links only to environment hosts; found {bad[:3]}")
    if IMAGE.search(text):
        errs.append(f"{where}: images are not allowed")
    return errs


def _path_errors(host: str, path: str, users: set[str], what: str) -> list[str]:
    if ".." in path.split("/") or "//" in path or path.endswith("/"):
        return [f"{host}: unsafe path {path}"]
    errs = []
    if not path.startswith(ALLOWED_PREFIXES):
        errs.append(f"{host}: {path} is outside allowed locations {ALLOWED_PREFIXES}")
    if path.startswith("/home/") and path.split("/")[2] not in users:
        errs.append(f"{host}: {what} {path} is in the home of unknown user {path.split('/')[2]}")
    return errs


def validate_spec(spec: EnvironmentSpec, cfg: BuildConfig) -> ValidationReport:
    r = ValidationReport()
    hosts = [d.hostname for d in spec.decoys]

    if len(hosts) != len(set(hosts)):
        r.errors.append("duplicate decoy hostnames")
    if len(hosts) > cfg.max_total_decoys:
        r.errors.append(f"more than {cfg.max_total_decoys} decoys")
    for h in hosts:
        if h in RESERVED_HOSTS:
            r.errors.append(f"hostname {h} is reserved for Mirage's own services")
        elif TELLTALE.search(h):
            r.errors.append(f"hostname {h} gives the honeypot away")
        if h in cfg.real_hosts:
            r.errors.append(f"hostname {h} collides with a real host")

    if not any(u.weak_password for d in spec.decoys for u in d.users):
        r.errors.append("no decoy has a weak-password user: attackers would have no way in")

    for d in spec.decoys:
        users = {u.username for u in d.users}
        if len(users) != len(d.users):
            r.errors.append(f"{d.hostname}: duplicate usernames")
        paths = [b.path for b in d.breadcrumbs]
        if len(paths) != len(set(paths)):
            r.errors.append(f"{d.hostname}: two breadcrumbs at the same path")
        for b in d.breadcrumbs:
            if ".." in b.path.split("/") or "//" in b.path or b.path.endswith("/"):
                r.errors.append(f"{d.hostname}: unsafe path {b.path}")
            elif not b.path.startswith(ALLOWED_PREFIXES):
                r.errors.append(f"{d.hostname}: {b.path} is outside allowed locations {ALLOWED_PREFIXES}")
            if b.points_to is not None:
                if b.points_to == d.hostname:
                    r.errors.append(f"{d.hostname}: breadcrumb {b.path} points to its own host")
                elif b.points_to not in hosts:
                    r.errors.append(f"{d.hostname}: breadcrumb {b.path} points to unknown host {b.points_to}")
            if b.owner is not None and b.owner not in users:
                r.errors.append(f"{d.hostname}: breadcrumb owner {b.owner} is not a user of this decoy")
            if b.path.startswith("/home/"):
                home_user = b.path.split("/")[2]
                if home_user not in users:
                    r.errors.append(f"{d.hostname}: {b.path} is in the home of unknown user {home_user}")

    tool_names = [t.name for t in spec.mcp_decoy_tools]
    if len(tool_names) != len(set(tool_names)):
        r.errors.append("duplicate decoy tool names")
    for t in tool_names:
        if t in cfg.real_tool_names:
            r.errors.append(f"decoy tool {t} would shadow a real tool")

    # The environment must not itself carry hidden instructions (tool poisoning) or links (exfil channels)
    for where, text in _free_text(spec):
        hits = scan_text(text)
        if hits:
            r.errors.append(f"{where} contains instruction-like text {list(hits)}: possible tool poisoning")
        if URL.search(text):
            r.errors.append(f"{where} contains a link or image markup")

    # Slots: the three decoy containers are fixed; each designed decoy fills one of them
    slots = [d.slot for d in spec.decoys]
    if any(slots) or cfg.require_slots:
        if not all(slots):
            r.errors.append(f"every decoy needs a slot ({', '.join(SLOTS)})")
        elif len(slots) != len(set(slots)):
            r.errors.append("two decoys in the same slot")

    for d in spec.decoys:
        users = {u.username for u in d.users}
        crumb_paths = {b.path for b in d.breadcrumbs}
        for p in d.spare_paths:
            r.errors.extend(_path_errors(d.hostname, p, users, "spare path"))
            if p in crumb_paths:
                r.errors.append(f"{d.hostname}: spare path {p} is already a breadcrumb")
        if len(d.spare_paths) != len(set(d.spare_paths)):
            r.errors.append(f"{d.hostname}: duplicate spare paths")

    usernames = [e.username for e in spec.employees]
    if len(usernames) != len(set(usernames)):
        r.errors.append("duplicate employee usernames")
    titles = [w.title.lower() for w in spec.wiki_pages]
    if len(titles) != len(set(titles)):
        r.errors.append("duplicate wiki page titles")

    world_hosts = set(hosts) | {cfg.wiki_host}
    for where, text in _contents(spec):
        r.errors.extend(content_check(where, text, world_hosts))

    by_host = {d.hostname: d for d in spec.decoys}
    for d in spec.decoys:
        for b in d.breadcrumbs:
            target = by_host.get(b.points_to or "")
            # without content, render.py gives the target a canary login itself; agent-written content can't know it
            if target and b.content is not None and not any(u.canary_password for u in target.users):
                r.warnings.append(f"{d.hostname}:{b.path} leads to {target.hostname}, but no user there logs in "
                                  "with a canary password: the credential found will not open it")

    if len(spec.decoys) > 1 and not any(b.points_to for d in spec.decoys for b in d.breadcrumbs):
        r.warnings.append("no breadcrumb leads to another decoy: attackers have no lateral path to follow")
    if not spec.mcp_decoy_tools and not spec.honey_docs and not spec.canary_keys:
        r.warnings.append("no AI-agent traps (decoy tools, honey docs, canary keys)")
    return r
