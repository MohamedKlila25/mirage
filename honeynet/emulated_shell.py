"""In-process decoy shell: the no-Docker substitute for Cowrie on this laptop.

It serves exactly what builder/render.py wrote (real hostnames, userdb passwords, honeyfs file
contents) and writes Cowrie-format JSON log lines to <log_root>/<slot>/log/cowrie/cowrie.json,
so the collector, enricher, ATT&CK mapping and everything downstream run unchanged. The same
environment is verified to load in real Cowrie 3.1.1 on a Linux host; this is the fast local path.

It implements the crawler's SSHConnector protocol, so the reactive crawler drives it the same
way it would drive real Cowrie over SSH.
"""
from __future__ import annotations

import fnmatch
import json
import re
import secrets
import time
from pathlib import Path


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _Log:
    """Appends Cowrie-format events for one decoy slot (one file per slot, like real Cowrie)."""

    def __init__(self, log_root: Path, slot: str):
        self.path = Path(log_root) / slot / "log" / "cowrie" / "cowrie.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **fields):
        rec = {"sensor": "vm", "timestamp": _now_iso(), **fields}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class EmulatedSession:
    def __init__(self, decoy: "EmulatedDecoy", user: str, session: str, src_ip: str, src_port: int):
        self.decoy, self.user, self.session, self.src_ip, self.src_port = decoy, user, session, src_ip, src_port
        self._start = time.monotonic()

    def run(self, command: str) -> str:
        self.decoy.log.write(eventid="cowrie.command.input", session=self.session, src_ip=self.src_ip,
                             src_port=self.src_port, input=command)
        return self.decoy.execute(self.user, command)

    def close(self):
        self.decoy.log.write(eventid="cowrie.session.closed", session=self.session, src_ip=self.src_ip,
                             src_port=self.src_port, duration_ms=int((time.monotonic() - self._start) * 1000))


class EmulatedDecoy:
    """One decoy: its logins and a tiny shell. File contents are read LIVE from the honeyfs dir on
    disk, so a breadcrumb the agent plants mid-attack appears on the next command, just as real
    Cowrie re-reads contents each session."""

    def __init__(self, slot: str, hostname: str, logins: dict[str, str], base: Path, log: _Log):
        self.slot, self.hostname, self.logins, self.base, self.log = slot, hostname, logins, Path(base), log

    def _paths(self) -> dict[str, Path]:
        if not self.base.is_dir():
            return {}
        return {"/" + f.relative_to(self.base).as_posix(): f for f in self.base.rglob("*") if f.is_file()}

    @property
    def files(self) -> dict[str, str]:
        return {p: f.read_text(errors="replace") for p, f in self._paths().items()}

    def execute(self, user: str, command: str) -> str:
        """Enough of a shell that an LLM attacker gets realistic feedback: compound commands
        (&&, ||, ;), stderr redirects, and pipes to grep/head/tail."""
        home = "/root" if user == "root" else f"/home/{user}"
        paths = self._paths()
        out = []
        for part in re.split(r"\s*(?:&&|\|\||;)\s*", command.strip()):
            if part.strip():
                out.append(self._one(part.strip(), user, home, paths))
        return "".join(out)

    def _one(self, cmd: str, user: str, home: str, paths: dict) -> str:
        segs = re.split(r"\s*\|\s*", cmd)
        base = segs[0]
        base = re.sub(r"\s*\d?>>?\s*\S+", "", base)          # drop > file, 2>/dev/null, >>log
        base = base.replace("2>&1", "").replace("~", home).strip()
        res = self._dispatch(base, user, home, paths)
        for seg in segs[1:]:                                  # pipes
            seg = seg.strip()
            if seg.startswith("grep"):
                m = re.search(r"grep\s+(?:-\w+\s+)*['\"]?([^'\"]+?)['\"]?$", seg)
                if m:
                    pat = m.group(1)
                    res = "".join(l + "\n" for l in res.splitlines() if re.search(pat.replace("\\|", "|"), l, re.I))
            elif seg.startswith("head"):
                n = int((re.search(r"-n?\s*(\d+)", seg) or [0, 10])[1]); res = "".join(l + "\n" for l in res.splitlines()[:n])
            elif seg.startswith("tail"):
                n = int((re.search(r"-n?\s*(\d+)", seg) or [0, 10])[1]); res = "".join(l + "\n" for l in res.splitlines()[-n:])
            elif seg.startswith(("wc", "sort", "uniq", "cut", "awk")):
                pass
        return res

    def _dispatch(self, cmd: str, user: str, home: str, paths: dict) -> str:
        if not cmd:
            return ""
        word = cmd.split()[0]
        if word == "whoami":
            return user + "\n"
        if word == "id":
            uid = 0 if user == "root" else 1000
            return f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})\n"
        if word == "hostname":
            return self.hostname + "\n"
        if word == "pwd":
            return home + "\n"
        if word == "uname":
            return "Linux " + self.hostname + " 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        if word in ("echo", "export", "history", "sudo", "touch", "mkdir", "rm", "chmod", "file", "head", "tail"):
            return ""
        if word == "env":
            return f"USER={user}\nHOME={home}\nSHELL=/bin/bash\nHOSTNAME={self.hostname}\nPWD={home}\n"
        if word == "find":
            return self._find(cmd, paths)
        if word == "cat":
            out = []
            for tok in cmd.split()[1:]:
                if tok.startswith("-"):
                    continue
                tok = tok if tok.startswith("/") else f"{home}/{tok}"
                f = paths.get(tok)
                out.append(f.read_text(errors="replace").rstrip("\n") if f else f"cat: {tok}: No such file or directory")
            return ("\n".join(out) + "\n") if out else ""
        if word in ("ls", "ll", "dir"):
            toks = [t for t in cmd.split()[1:] if not t.startswith("-")]
            d = (toks[0] if toks else home)
            d = (d if d.startswith("/") else f"{home}/{d}").rstrip("/") or ""
            if d in paths:                                   # ls of a file
                return d.rsplit("/", 1)[-1] + "\n"
            names = sorted({p[len(d) + 1:].split("/")[0] for p in paths if p.startswith(d + "/")})
            return ("\n".join(names) + "\n") if names else (f"ls: cannot access '{d}': No such file or directory\n")
        if word in ("grep", "egrep"):                        # grep PATTERN FILE...
            m = re.search(r"grep\s+(?:-\w+\s+)*['\"]?([^'\"\s]+)['\"]?\s+(.+)$", cmd)
            if m:
                pat, files = m.group(1), m.group(2).split()
                out = []
                for tok in files:
                    tok = tok if tok.startswith("/") else f"{home}/{tok}"
                    f = paths.get(tok)
                    if f:
                        out += [l for l in f.read_text(errors="replace").splitlines() if re.search(pat, l, re.I)]
                return ("\n".join(out) + "\n") if out else ""
        return ""

    def _find(self, cmd: str, paths: dict) -> str:
        toks = cmd.split()
        roots = [t for t in toks[1:] if t.startswith("/") or t == "."]
        roots = [("/" if r == "." else r).rstrip("/") or "" for r in roots] or [""]
        names = re.findall(r"-i?name\s+['\"]?([^'\"\s]+)['\"]?", cmd)
        hits = []
        for p in sorted(paths):
            if not any(p == r or p.startswith(r + "/") or r == "" for r in roots):
                continue
            if names and not any(fnmatch.fnmatch(p.rsplit("/", 1)[-1], g) for g in names):
                continue
            hits.append(p)
        return ("\n".join(hits) + "\n") if hits else ""


class EmulatedHoneynet:
    """Connector the crawler uses. Verifies credentials against the rendered userdb and logs logins."""

    def __init__(self, deception_dir: Path, render_dir: Path, world: dict, log_root: Path,
                 src_ip: str = "10.100.0.9"):
        self.src_ip = src_ip
        self.deception_dir = Path(deception_dir)
        self.decoys: dict[str, EmulatedDecoy] = {}
        self._slot_base: dict[str, Path] = {}
        self.connections: list[tuple] = []        # (host, user, password) attempts, for tests/metrics
        for h in world["hosts"]:
            slot, hostname = h["slot"], h["hostname"]
            base = self.deception_dir / slot
            self._slot_base[slot] = base
            logins = {}
            udb = Path(render_dir) / slot / "etc" / "userdb.txt"
            if udb.is_file():
                for line in udb.read_text().splitlines():
                    if line and not line.startswith("#") and ":x:" in line:
                        u, p = line.split(":x:", 1)
                        logins[u] = p
            self.decoys[hostname] = EmulatedDecoy(slot, hostname, logins, base, _Log(log_root, slot))

    def connect(self, host, port, user, password):
        self.connections.append((host, user, password))
        decoy = self.decoys.get(host)
        session = secrets.token_hex(6)
        if decoy is None:
            return None
        decoy.log.write(eventid="cowrie.session.connect", session=session, src_ip=self.src_ip, src_port=port)
        if decoy.logins.get(user) == password:
            decoy.log.write(eventid="cowrie.login.success", session=session, src_ip=self.src_ip, src_port=port,
                            username=user, password=password)
            return EmulatedSession(decoy, user, session, self.src_ip, port)
        decoy.log.write(eventid="cowrie.login.failed", session=session, src_ip=self.src_ip, src_port=port,
                        username=user, password=password)
        return None

    def reload_files(self):
        """No-op: decoys read file contents live from disk, so planted files appear immediately."""
