"""Render an approved EnvironmentSpec into the files the decoys read. Code, not the LLM, writes here.

Per decoy slot (fake-jump-01, fake-db-01, fake-ftp-01):
  <deception_dir>/<slot>/...           file contents (Cowrie [honeypot] contents_path, read-only mount)
  <render_dir>/<slot>/fs.pickle        Cowrie filesystem: base minus fingerprints, plus every planted path
  <render_dir>/<slot>/etc/userdb.txt   who can log in (closed slots: nobody until open_decoy_service)
Shared:
  <deception_dir>/wiki/[internal/]*.md     wiki pages (internal = tier 2)
  <deception_dir>/manifest.json            per slot, the paths mirage-control may later rewrite
  <render_dir>/compose.override.yml        displayed hostnames and network aliases per slot
  <render_dir>/world_model.json            what the agent may know: names only, never credential values

Credential values come only from the canary registry (placeholders in the spec) or, for the
entry point's guessable password, from a fixed list chosen by code.
"""
from __future__ import annotations

import copy
import json
import re
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from canary.registry import CanaryRegistry

from . import cowrie_fs as cfs
from .spec import SLOTS, BreadcrumbSpec, DecoySpec, EnvironmentSpec
from .validate import BuildConfig, validate_spec

WEAK_PASSWORDS = ("Summer2024!", "Welcome1", "admin123", "Passw0rd!", "changeme", "qwerty123")


class RenderError(Exception):
    pass


@dataclass
class RenderConfig:
    deception_dir: Path
    render_dir: Path
    base_fs: Path = Path(__file__).resolve().parents[1] / "honeynet" / "cowrie" / "base_fs.pickle"
    closed_slots: tuple[str, ...] = ("fake-ftp-01",)             # opened by open_decoy_service (tier 3)
    wiki_host: str = "wiki"
    build: BuildConfig = field(default_factory=lambda: BuildConfig(require_slots=True))


def slugify(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60] or "page"


class _Counter:
    """Next free canary number per kind, so code-made placeholders never collide with the agent's."""

    def __init__(self, spec_text: str):
        self.next = {}
        for kind, n in re.findall(r"\{\{\s*canary:([a-z_]+?)_(\d{1,3})\s*\}\}", spec_text):
            self.next[kind] = max(self.next.get(kind, 1), int(n) + 1)

    def placeholder(self, kind: str) -> str:
        n = self.next.get(kind, 1)
        self.next[kind] = n + 1
        return f"{{{{canary:{kind}_{n}}}}}"


def _target(spec: EnvironmentSpec, hostname: str | None) -> DecoySpec | None:
    return next((d for d in spec.decoys if d.hostname == hostname), None)


def pivot_logins(spec: EnvironmentSpec, counter: _Counter) -> dict[tuple[str, str], str]:
    """For each decoy a breadcrumb leads to: (hostname, user) -> password placeholder that opens it.
    The design's canary_password if it has one, else code gives the host's first user a new canary."""
    logins: dict[tuple[str, str], str] = {}
    for d in spec.decoys:
        for u in d.users:
            if u.canary_password:
                logins[(d.hostname, u.username)] = u.canary_password
    targets = {b.points_to for d in spec.decoys for b in d.breadcrumbs if b.points_to}
    for d in spec.decoys:
        if d.hostname in targets and not any(h == d.hostname for h, _ in logins):
            logins[(d.hostname, d.users[0].username)] = counter.placeholder("password")
    return logins


def _login_for(target: DecoySpec | None, logins: dict, counter: _Counter) -> tuple[str, str]:
    if target:
        for (h, user), pw in logins.items():
            if h == target.hostname:
                return user, pw
    return "admin", counter.placeholder("password")


def default_content(b: BreadcrumbSpec, spec: EnvironmentSpec, counter: _Counter, logins: dict) -> str:
    """Used only when the agent gave no content for a breadcrumb. Credentials stay placeholders."""
    target = _target(spec, b.points_to)
    user, pw = _login_for(target, logins, counter)
    host = b.points_to or "localhost"
    if b.kind == "env_file":
        return f"APP_ENV=production\nDB_HOST={host}\nDB_PORT=5432\nDB_USER={user}\nDB_PASSWORD={pw}\n"
    if b.kind == "credentials_note":
        return f"{host}\n  user: {user}\n  pass: {pw}\n"
    if b.kind == "ssh_config":
        return f"Host {host}\n    HostName {host}\n    User {user}\n"
    if b.kind == "db_dump":
        return (f"-- {spec.company} customers export\nCREATE TABLE customers (id int, email text, plan text);\n"
                f"INSERT INTO customers VALUES (1, 'billing@{spec.company.lower().replace(' ', '')}.com', 'enterprise');\n"
                f"-- replication user {user} / {pw}\n")
    return f"Notes\n- access to {host}: ask {user}\n"


def _without_user(text: bytes | None, user: str) -> list[str]:
    """Drop a user's own line and its membership in groups (last field of /etc/group)."""
    out = []
    for line in (text or b"").decode("ascii", "replace").splitlines():
        if not line or line.startswith(user + ":"):
            continue
        parts = line.split(":")
        if len(parts) == 4:
            parts[3] = ",".join(m for m in parts[3].split(",") if m and m != user)
        out.append(":".join(parts))
    return out


def _passwd_group(base_tree, users: list[tuple[str, int]]) -> tuple[str, str]:
    """/etc/passwd and /etc/group: Cowrie's base minus its default user, plus the designed users."""
    passwd = _without_user(cfs.read_bytes(base_tree, "/etc/passwd"), "phil")
    group = _without_user(cfs.read_bytes(base_tree, "/etc/group"), "phil")
    passwd += [f"{u}:x:{uid}:{uid}:{u},,,:/home/{u}:/bin/bash" for u, uid in users if u != "root"]
    group += [f"{u}:x:{uid}:" for u, uid in users if u != "root"]
    return "\n".join(passwd) + "\n", "\n".join(group) + "\n"


DEEP_KINDS = ("env_file", "credentials_note", "db_dump", "ssh_config")


def render_environment(spec: EnvironmentSpec, registry: CanaryRegistry, cfg: RenderConfig,
                       env_id: str, db=None, shallow: bool = False) -> dict:
    """shallow=True renders a basic/classic honeypot: no credential lures that lead the attacker
    deeper and no pivot logins, so the attacker can't easily move past the entry host. Used as the
    static baseline for the static-vs-agent comparison; the agent (adaptive) gets the full environment."""
    report = validate_spec(spec, cfg.build)
    if not report.ok:
        raise RenderError("; ".join(report.errors))
    base = cfs.load(cfg.base_fs)
    counter = _Counter(spec.model_dump_json())
    logins = {} if shallow else pivot_logins(spec, counter)
    manifest: dict[str, list[str]] = {}
    decoy_records: list[dict] = []
    override: dict = {"services": {}}

    for slot in SLOTS:                                   # generated output only: rebuilt from the spec
        shutil.rmtree(cfg.deception_dir / slot, ignore_errors=True)
        shutil.rmtree(cfg.render_dir / slot, ignore_errors=True)
    shutil.rmtree(cfg.deception_dir / "wiki", ignore_errors=True)

    for d in spec.decoys:
        slot, honeyfs, out = d.slot, cfg.deception_dir / d.slot, cfg.render_dir / d.slot
        tree = copy.deepcopy(base)
        for p in cfs.FINGERPRINTS:
            cfs.remove(tree, p)

        uids = {u.username: (0 if u.username == "root" else 1000 + i) for i, u in enumerate(d.users)}
        for u, uid in uids.items():
            if u != "root":
                cfs.mkdirs(tree, f"/home/{u}", uid, uid)

        def write(path: str, text: str, uid: int = 0, mode: int = cfs.FILE_MODE) -> list[str]:
            final, used = registry.substitute(text, where={"host": slot, "path": path})
            data = final.encode()
            dest = honeyfs / path.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            cfs.put_file(tree, path, len(data), uid, uid, mode)
            return used

        passwd, group = _passwd_group(base, list(uids.items()))
        write("/etc/passwd", passwd)
        write("/etc/group", group)
        write("/etc/hostname", d.hostname + "\n")

        paths = []
        for b in d.breadcrumbs:
            if shallow and (b.points_to or b.kind in DEEP_KINDS):
                continue                                 # a basic honeypot has no deep credential lures
            owner = b.owner or (b.path.split("/")[2] if b.path.startswith("/home/") else None)
            mode = cfs.PRIVATE_MODE if b.kind in ("ssh_config", "credentials_note") else cfs.FILE_MODE
            used = write(b.path, b.content if b.content is not None else default_content(b, spec, counter, logins),
                         uids.get(owner, 0), mode)
            paths.append(b.path)
            decoy_records.append({"host": slot, "kind": "file", "path": b.path, "canaries": [f"canary:{c}" for c in used],
                                  "reason": f"environment {env_id}: {b.kind}"})
        for p in d.spare_paths:
            owner = p.split("/")[2] if p.startswith("/home/") else None
            write(p, "", uids.get(owner, 0))
            paths.append(p)
        manifest[slot] = paths

        lines = []
        for u in d.users:
            placeholder = logins.get((d.hostname, u.username))
            if placeholder:
                pw, _ = registry.substitute(placeholder, where={"host": slot, "path": "login:" + u.username})
            elif u.weak_password:
                pw = secrets.choice(WEAK_PASSWORDS)
            else:
                pw = secrets.token_urlsafe(18)
            lines.append(f"{u.username}:x:{pw}")
        userdb = "\n".join(lines) + "\n"
        (out / "etc").mkdir(parents=True, exist_ok=True)
        if slot in cfg.closed_slots:
            (out / "etc" / "userdb.txt").write_text("# closed: no login until the analyst opens this decoy\n")
            (out / "etc" / "userdb.open.txt").write_text(userdb)
        else:
            (out / "etc" / "userdb.txt").write_text(userdb)
        cfs.dump(tree, out / "fs.pickle")

        override["services"][slot] = {
            "hostname": d.hostname,
            "environment": {"COWRIE_HONEYPOT_HOSTNAME": d.hostname},
            "networks": {"attack-net": {"aliases": [d.hostname]}},
        }

    world_hosts = {d.hostname for d in spec.decoys} | {cfg.wiki_host}
    for w in spec.wiki_pages:
        if shallow and w.section == "internal":
            continue                                     # basic honeypot: no deep internal wiki lures
        rel = ("internal/" if w.section == "internal" else "") + slugify(w.title) + ".md"
        final, used = registry.substitute(f"# {w.title}\n\n{w.markdown}\n", where={"host": "wiki", "path": "/" + rel})
        dest = cfg.deception_dir / "wiki" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(final)
        decoy_records.append({"host": "wiki", "kind": "wiki_page", "path": "/" + rel[:-3], "canaries": [f"canary:{c}" for c in used],
                              "reason": f"environment {env_id}: wiki ({w.section})"})

    world = {
        "env_id": env_id, "company": spec.company, "sector": spec.sector, "product": spec.product,
        "stack": spec.stack, "employees": [e.model_dump() for e in spec.employees],
        "hosts": [{"slot": d.slot, "hostname": d.hostname, "role": d.role, "users": [u.username for u in d.users],
                   "closed": d.slot in cfg.closed_slots} for d in spec.decoys],
        "wiki": {"host": cfg.wiki_host, "pages": [{"title": w.title, "section": w.section} for w in spec.wiki_pages]},
        "world_hosts": sorted(world_hosts),
        "mcp_decoy_tools": [t.name for t in spec.mcp_decoy_tools],
        "honey_docs": [h.title for h in spec.honey_docs],
        "manifest": manifest,                 # paths the agent may write to (Cowrie only shows these)
    }
    cfg.render_dir.mkdir(parents=True, exist_ok=True)
    (cfg.render_dir / "world_model.json").write_text(json.dumps(world, indent=2))
    (cfg.render_dir / "compose.override.yml").write_text(
        "# Generated by builder/render.py from an approved environment. Do not edit.\n" + yaml.safe_dump(override))
    cfg.deception_dir.mkdir(parents=True, exist_ok=True)
    (cfg.deception_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    if db is not None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        db["decoys"].delete_many({"session_id": "environment"})
        for r in decoy_records:
            db["decoys"].insert_one({"decoy_id": "dec-" + secrets.token_hex(4), "session_id": "environment",
                                     "policy": "static", "evidence": [], "created_at": now, "touched_by": [], **r})
        db["world_model"].replace_one({"_id": "current"}, {"_id": "current", **world}, upsert=True)
    return {"env_id": env_id, "manifest": manifest, "decoys": len(decoy_records), "warnings": report.warnings,
            "world_hosts": sorted(world_hosts)}
