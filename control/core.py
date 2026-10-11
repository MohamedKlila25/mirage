"""mirage-control core: the only way any policy changes the honeynet.

Every call goes through the same checks, in this order, and is recorded whatever happens:
  kill switch (agent calls) -> allowlist -> parameter schema -> evidence -> tool checks/caps
Then: small moves execute at once; big moves become a pending approval for the analyst,
rejected automatically after 10 minutes. Outputs are files in /deception (read by the decoys
and the wiki) and /control (read by the decoys, the company MCP server, exports).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from brain.policies.base import MAX_TIER, TOOLS
from builder.validate import ALLOWED_PREFIXES, content_check
from canary.registry import CanaryRegistry
from reliability.audit import AuditLog
from reliability.policy import PolicyConfig, _is_never_block

HOST = r"^[a-z][a-z0-9-]{2,30}$"
TECH = r"^T\d{4}(\.\d{3})?$"


class _P(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ObserveP(_P):
    session_id: str
    note: str = Field(max_length=2000)


class PlantP(_P):
    """Either a template file name, or content written by the agent (credentials as canary placeholders)."""
    host: str = Field(pattern=HOST)
    path: str = Field(pattern=r"^/[A-Za-z0-9_./-]{1,120}$")
    template: str | None = Field(default=None, pattern=r"^[a-z0-9_]{2,40}$")
    content: str | None = Field(default=None, min_length=1, max_length=4096)

    @model_validator(mode="after")
    def _one_source(self):
        if (self.template is None) == (self.content is None):
            raise ValueError("give exactly one of template or content")
        return self


class WikiP(_P):
    title: str = Field(min_length=3, max_length=80)
    markdown: str = Field(min_length=1, max_length=8192)


class TagP(_P):
    session_id: str
    actor: Literal["human", "bot", "ai_agent", "unknown"]
    objective: str = Field(min_length=1, max_length=64)
    techniques: list[str] = Field(default_factory=list, max_length=30)


class EscalateP(_P):
    session_id: str
    tier: int = Field(ge=2, le=MAX_TIER)


class OpenServiceP(_P):
    name: str


class BlockP(_P):
    ioc: str = Field(min_length=3, max_length=255)


class RevokeP(_P):
    agent_id: str = Field(min_length=1, max_length=64)


class DisableToolP(_P):
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")


PARAMS = {"observe": ObserveP, "plant_breadcrumb": PlantP, "create_wiki_page": WikiP, "tag_session": TagP,
          "escalate_tier": EscalateP, "open_decoy_service": OpenServiceP, "recommend_block": BlockP,
          "revoke_agent_token": RevokeP, "disable_mcp_tool": DisableToolP}
assert set(PARAMS) == set(TOOLS)

URL = re.compile(r"https?://([^/\s)\"'>]+)", re.IGNORECASE)


@dataclass
class ControlConfig:
    deception_dir: Path
    control_dir: Path
    templates_dir: Path                                   # Mirage's static breadcrumb files
    exports_dir: Path
    allowed_prefixes: tuple[str, ...] = ALLOWED_PREFIXES
    decoy_hosts: set[str] = field(default_factory=lambda: {"fake-jump-01", "fake-db-01", "fake-ftp-01"})
    world_hosts: set[str] = field(default_factory=lambda: {"wiki.internal", "fake-jump-01", "fake-db-01", "fake-ftp-01"})
    decoy_services: set[str] = field(default_factory=lambda: {"fake-ftp-01"})
    plants_per_batch: int = 3
    plants_per_session: int = 10
    max_template_bytes: int = 4096
    approval_ttl_s: int = 600
    never_block: PolicyConfig = field(default_factory=PolicyConfig)
    manifest_path: Path | None = None    # set in production: decoy paths Cowrie knows (builder/render.py)
    render_dir: Path | None = None       # rendered decoy config; open_decoy_service enables logins there


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _write_json_atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


class MirageControl:
    def __init__(self, db, cfg: ControlConfig, audit: AuditLog, clock: Callable[[], datetime] = _now):
        self.db, self.cfg, self.audit, self.clock = db, cfg, audit, clock
        self.canaries = CanaryRegistry(db)
        db["actions"].create_index("action_id", unique=True)

    def world_hosts(self) -> set[str]:
        """Hosts decoy text may link to: the rendered environment's, else the configured default."""
        wm = self.db["world_model"].find_one({"_id": "current"}) or {}
        return set(wm.get("world_hosts") or []) | set(self.cfg.world_hosts)

    # ------------------------------------------------------------------ kill switch
    def kill_switch_on(self) -> bool:
        doc = self.db["control"].find_one({"_id": "kill_switch"})
        return bool(doc and doc.get("on"))

    def set_kill_switch(self, on: bool, by: str) -> None:
        self.db["control"].update_one({"_id": "kill_switch"}, {"$set": {"on": on, "by": by, "at": self.clock()}}, upsert=True)
        self.audit.append("kill_switch", on=on, by=by)

    # ------------------------------------------------------------------ main entry
    def call(self, tool: str, params: dict, reason: str, evidence: list[str], policy: str,
             session_id: str, batch_id: str = "") -> dict:
        rec = {"action_id": "act-" + uuid.uuid4().hex[:10], "ts": self.clock(), "session_id": session_id,
               "batch_id": batch_id, "policy": policy, "tool": tool, "params": params, "risk": TOOLS.get(tool),
               "reason": (reason or "")[:500], "evidence": list(evidence or []), "status": None, "blocked_by": None,
               "detail": "", "decided_by": None, "decided_at": None, "reject_reason": None}

        blocked = self._check(rec)
        if not blocked and rec["risk"] == "approval" and self.db["actions"].find_one(
                {"session_id": session_id, "tool": tool, "params": params, "status": "pending"}):
            blocked = ("cap", "an identical action is already waiting for approval")
        if blocked:
            rec["status"], (rec["blocked_by"], rec["detail"]) = "blocked", blocked
        elif rec["risk"] == "approval":
            rec["status"], rec["detail"] = "pending", "waiting for analyst approval"
        else:
            rec["status"], rec["detail"] = "executed", self._execute(rec)
        self.db["actions"].insert_one(dict(rec))
        self.audit.append("control_call", **{k: v for k, v in rec.items() if k != "ts"})
        return {k: rec[k] for k in ("action_id", "status", "blocked_by", "detail")}

    # ------------------------------------------------------------------ checks
    def _check(self, rec) -> tuple[str, str] | None:
        tool, params, sid = rec["tool"], rec["params"], rec["session_id"]
        if rec["policy"] != "static" and self.kill_switch_on():
            return "kill_switch", "kill switch is on: agent calls are refused, static policy runs"
        if tool not in TOOLS:
            return "allowlist", f"tool '{tool}' is not allowed"
        try:
            p = PARAMS[tool].model_validate(params)
        except ValidationError as e:
            return "schema", "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())[:500]
        if not rec["reason"].strip():
            return "schema", "a reason is required"
        if not rec["evidence"]:
            return "evidence", "at least one event id is required"
        found = {e["event_id"] for e in self.db["events"].find({"event_id": {"$in": rec["evidence"]}, "session_id": sid}, {"event_id": 1})}
        missing = [e for e in rec["evidence"] if e not in found]
        if missing:
            return "evidence", f"events not found in this session: {missing[:5]}"
        if getattr(p, "session_id", sid) != sid:
            return "schema", "session_id does not match the calling session"
        return getattr(self, f"_check_{tool}", lambda p, r: None)(p, rec)

    def _check_plant_breadcrumb(self, p: PlantP, rec):
        c = self.cfg
        if p.host not in c.decoy_hosts:
            return "schema", f"{p.host} is not a decoy"
        if ".." in p.path.split("/") or "//" in p.path or not p.path.startswith(c.allowed_prefixes):
            return "schema", f"path {p.path} is outside the allowed locations"
        if p.template is not None:
            tpl = c.templates_dir / p.template
            if not tpl.is_file():
                return "schema", f"unknown template {p.template}"
            if tpl.stat().st_size > c.max_template_bytes:
                return "cap", "template larger than the size limit"
        else:
            if len(p.content.encode()) > c.max_template_bytes:
                return "cap", "content larger than the size limit"
            errs = content_check("content", p.content, self.world_hosts())
            if errs:
                return "schema", "; ".join(errs)[:500]
        if c.manifest_path is not None:
            manifest = _read_json(c.manifest_path, None)
            if manifest is None:
                return "schema", "no rendered environment yet (manifest missing)"
            if p.path not in manifest.get(p.host, []):
                return "schema", (f"{p.path} is not in {p.host}'s filesystem; Cowrie only shows paths it was started "
                                  "with: use a spare path or a wiki page")
        in_batch = self.db["actions"].count_documents({"session_id": rec["session_id"], "batch_id": rec["batch_id"],
                                                       "tool": "plant_breadcrumb", "status": "executed"}) if rec["batch_id"] else 0
        if in_batch >= c.plants_per_batch:
            return "cap", f"max {c.plants_per_batch} breadcrumbs per batch"
        if self.db["decoys"].count_documents({"session_id": rec["session_id"]}) >= c.plants_per_session:
            return "cap", f"max {c.plants_per_session} decoys per session"
        if self.db["decoys"].find_one({"session_id": rec["session_id"], "host": p.host, "path": p.path}):
            return "schema", "already planted at this path"

    def _check_create_wiki_page(self, p: WikiP, rec):
        hosts = self.world_hosts()
        bad = [h for h in URL.findall(p.markdown) if h.split(":")[0].lower() not in hosts]
        if bad:
            return "schema", f"links only to world-model hosts; found {sorted(set(bad))[:3]}"
        if "](" in p.markdown and "![" in p.markdown:
            return "schema", "images are not allowed in wiki pages"
        errs = content_check("markdown", f"{p.title}\n{p.markdown}", hosts)
        if errs:
            return "schema", "; ".join(errs)[:500]
        if self.db["decoys"].count_documents({"session_id": rec["session_id"]}) >= self.cfg.plants_per_session:
            return "cap", f"max {self.cfg.plants_per_session} decoys per session"

    def _check_tag_session(self, p: TagP, rec):
        bad = [t for t in p.techniques if not re.match(TECH, t)]
        if bad:
            return "schema", f"invalid technique ids {bad[:3]}"

    def _check_escalate_tier(self, p: EscalateP, rec):
        cur = int((self.db["sessions"].find_one({"session_id": p.session_id}) or {}).get("tier", 1))
        if p.tier != cur + 1:
            return "schema", f"can only escalate one tier at a time (current {cur})"
        if self.db["actions"].find_one({"session_id": p.session_id, "tool": "escalate_tier", "status": "pending",
                                        "action_id": {"$ne": rec["action_id"]}}):
            return "cap", "an escalation is already waiting for approval"

    def _check_open_decoy_service(self, p: OpenServiceP, rec):
        if p.name not in self.cfg.decoy_services:
            return "schema", f"{p.name} is not a predefined decoy service"

    def _check_recommend_block(self, p: BlockP, rec):
        if _is_never_block(p.ioc, self.cfg.never_block):
            return "never_block", f"{p.ioc} is on the never-block list"

    def _check_revoke_agent_token(self, p: RevokeP, rec):
        if not self.db["agents"].find_one({"agent_id": p.agent_id}):
            return "schema", f"unknown agent {p.agent_id}"

    def _check_disable_mcp_tool(self, p: DisableToolP, rec):
        if not self.db["mcp_tools"].find_one({"name": p.tool_name}):
            return "schema", f"unknown tool {p.tool_name}"

    # ------------------------------------------------------------------ execution
    def _execute(self, rec) -> str:
        return getattr(self, f"_exec_{rec['tool']}")(rec["params"], rec)

    def _exec_observe(self, params, rec):
        return "observed"

    def _safe_target(self, host: str, path: str) -> Path:
        base = self.cfg.deception_dir.resolve()
        root = (base / host).resolve()
        target = (root / path.lstrip("/")).resolve()
        if root.parent != base or root not in target.parents:
            raise ValueError("path escapes the deception folder")
        return target

    def _record_decoy(self, rec, host, kind, path, canaries=()):
        self.db["decoys"].insert_one({"decoy_id": "dec-" + uuid.uuid4().hex[:8], "session_id": rec["session_id"],
                                      "host": host, "kind": kind, "path": path, "policy": rec["policy"],
                                      "canaries": [f"canary:{c}" for c in canaries],
                                      "reason": rec["reason"], "evidence": rec["evidence"],
                                      "action_id": rec["action_id"], "created_at": self.clock(), "touched_by": []})

    def _exec_plant_breadcrumb(self, params, rec):
        target = self._safe_target(params["host"], params["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if params.get("content") is not None:
            text, used = self.canaries.substitute(params["content"], where={"host": params["host"], "path": params["path"]})
            target.write_text(text)
            self._record_decoy(rec, params["host"], "file", params["path"], used)
            return f"planted agent content at {params['host']}:{params['path']}"
        shutil.copyfile(self.cfg.templates_dir / params["template"], target)
        self._record_decoy(rec, params["host"], "file", params["path"])
        return f"planted {params['template']} at {params['host']}:{params['path']}"

    def _exec_create_wiki_page(self, params, rec):
        slug = re.sub(r"[^a-z0-9]+", "-", params["title"].lower()).strip("-")[:60] or "page"
        target = self._safe_target("wiki", f"/{slug}.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        text, used = self.canaries.substitute(f"# {params['title']}\n\n{params['markdown']}\n",
                                              where={"host": "wiki", "path": f"/{slug}"})
        target.write_text(text)
        self._record_decoy(rec, "wiki", "wiki_page", f"/{slug}", used)
        return f"wiki page /{slug}"

    def _exec_tag_session(self, params, rec):
        self.db["sessions"].update_one({"session_id": params["session_id"]}, {"$set": {
            "profile": {"actor": params["actor"], "objective": params["objective"]},
            "techniques": params.get("techniques", []), "tagged_at": self.clock()}}, upsert=True)
        return "session tagged"

    def _exec_escalate_tier(self, params, rec):
        self.db["sessions"].update_one({"session_id": params["session_id"]}, {"$set": {"tier": params["tier"]}}, upsert=True)
        tiers = _read_json(self.cfg.control_dir / "tiers.json", {})
        tiers[params["session_id"]] = params["tier"]
        _write_json_atomic(self.cfg.control_dir / "tiers.json", tiers)
        return f"tier {params['tier']}"

    def _add_to_list(self, name, value):
        items = _read_json(self.cfg.control_dir / name, [])
        if value not in items:
            items.append(value)
        _write_json_atomic(self.cfg.control_dir / name, items)

    def _exec_open_decoy_service(self, params, rec):
        self._add_to_list("open_services.json", params["name"])
        if self.cfg.render_dir is not None:                 # Cowrie re-reads userdb.txt at every login attempt
            etc = self.cfg.render_dir / params["name"] / "etc"
            if (etc / "userdb.open.txt").is_file():
                shutil.copyfile(etc / "userdb.open.txt", etc / "userdb.txt")
        return f"opened {params['name']}"

    def _exec_recommend_block(self, params, rec):
        self.cfg.exports_dir.mkdir(parents=True, exist_ok=True)
        with (self.cfg.exports_dir / "iocs.jsonl").open("a") as f:
            f.write(json.dumps({"ioc": params["ioc"], "session_id": rec["session_id"], "action_id": rec["action_id"],
                                "approved_by": rec.get("decided_by"), "reason": rec["reason"]}) + "\n")
        return f"IOC {params['ioc']} exported"

    def _exec_revoke_agent_token(self, params, rec):
        self._add_to_list("revoked.json", params["agent_id"])
        return f"agent {params['agent_id']} revoked"

    def _exec_disable_mcp_tool(self, params, rec):
        self._add_to_list("disabled_tools.json", params["tool_name"])
        return f"tool {params['tool_name']} disabled"

    # ------------------------------------------------------------------ approvals (dashboard)
    def decide(self, action_id: str, decision: str, analyst: str, reason: str = "") -> dict:
        rec = self.db["actions"].find_one({"action_id": action_id}, {"_id": 0})
        if rec is None:
            raise KeyError(action_id)
        if rec["status"] != "pending":
            raise ValueError(f"action is {rec['status']}, not pending")
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        if decision == "reject" and not reason.strip():
            raise ValueError("a reason is required to reject")
        if decision == "approve" and self.kill_switch_on() and rec["policy"] != "static":
            raise ValueError("kill switch is on: agent actions cannot be approved")
        rec.update(decided_by=analyst, decided_at=self.clock())
        if decision == "approve":
            blocked = self._check({**rec, "status": None})  # re-check: the world may have changed
            if blocked:
                upd = {"status": "blocked", "blocked_by": blocked[0], "detail": blocked[1]}
            else:
                upd = {"status": "approved", "detail": self._execute(rec)}
        else:
            upd = {"status": "rejected", "reject_reason": reason}
        upd.update(decided_by=analyst, decided_at=rec["decided_at"])
        self.db["actions"].update_one({"action_id": action_id}, {"$set": upd})
        self.audit.append("approval_decision", action_id=action_id, decision=decision, analyst=analyst,
                          reason=reason, result=upd["status"])
        return self.db["actions"].find_one({"action_id": action_id}, {"_id": 0})

    def expire_pending(self) -> int:
        cutoff = self.clock() - timedelta(seconds=self.cfg.approval_ttl_s)
        n = 0
        for rec in self.db["actions"].find({"status": "pending"}):
            ts = rec["ts"] if rec["ts"].tzinfo else rec["ts"].replace(tzinfo=timezone.utc)
            if ts < cutoff:
                self.db["actions"].update_one({"action_id": rec["action_id"]}, {"$set": {
                    "status": "rejected", "reject_reason": "no answer within the approval window",
                    "decided_by": "system", "decided_at": self.clock()}})
                self.audit.append("approval_expired", action_id=rec["action_id"])
                n += 1
        return n
