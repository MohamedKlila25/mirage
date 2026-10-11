"""Build mode commands (run in the builder container: docker compose run --rm builder <command>).

  design [--brief TEXT]            the agent designs an environment -> stored as pending (or invalid)
  show <env_id>                    print the design and its validation report
  approve <env_id> <analyst>       a human approves -> rendered by code (data/deception, data/render)
  reject <env_id> <analyst> <why>  a reason is required
  render <env_id>                  re-render an approved design (resets decoys between experiment runs)

Then start or restart the decoys:
  docker compose -f docker-compose.yml -f data/render/compose.override.yml --profile decoys up -d --force-recreate
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from canary.registry import CanaryRegistry

from .agent import design_environment
from .render import RenderConfig, render_environment
from .spec import EnvironmentSpec
from .validate import BuildConfig, validate_spec


def _now():
    return datetime.now(timezone.utc)


class BuildService:
    def __init__(self, db, render_cfg: RenderConfig, call_llm=None, model: str = ""):
        self.db, self.render_cfg, self.call_llm, self.model = db, render_cfg, call_llm, model
        self.envs = db["environments"]
        self.envs.create_index("env_id", unique=True)

    def design(self, brief: str = "", max_attempts: int = 2) -> dict:
        res = design_environment(self.call_llm, brief, max_attempts=max_attempts)
        doc = {"env_id": "env-" + secrets.token_hex(4), "status": "pending" if res.spec and res.report.ok else "invalid",
               "spec": res.spec.model_dump() if res.spec else None, "errors": res.errors,
               "warnings": res.report.warnings, "brief": brief, "model": self.model, "attempts": len(res.raw),
               "created_at": _now(), "decided_by": None, "decided_at": None, "reason": None}
        self.envs.insert_one(dict(doc))
        return doc

    def get(self, env_id: str) -> dict:
        doc = self.envs.find_one({"env_id": env_id}, {"_id": 0})
        if doc is None:
            raise KeyError(env_id)
        return doc

    def approve(self, env_id: str, analyst: str) -> dict:
        doc = self.get(env_id)
        if doc["status"] != "pending":
            raise ValueError(f"environment is {doc['status']}, not pending")
        if not analyst.strip():
            raise ValueError("analyst name required")
        spec = EnvironmentSpec.model_validate(doc["spec"])
        report = validate_spec(spec, BuildConfig(require_slots=True))          # re-check before rendering
        if not report.ok:
            raise ValueError("design no longer valid: " + "; ".join(report.errors))
        out = render_environment(spec, CanaryRegistry(self.db), self.render_cfg, env_id, self.db)
        self.envs.update_many({"status": "approved", "active": True}, {"$set": {"active": False}})
        self.envs.update_one({"env_id": env_id}, {"$set": {"status": "approved", "active": True, "decided_by": analyst,
                                                           "decided_at": _now(), "rendered_at": _now()}})
        return out

    def reject(self, env_id: str, analyst: str, reason: str) -> None:
        doc = self.get(env_id)
        if doc["status"] != "pending":
            raise ValueError(f"environment is {doc['status']}, not pending")
        if not reason.strip():
            raise ValueError("a reason is required to reject")
        self.envs.update_one({"env_id": env_id}, {"$set": {"status": "rejected", "decided_by": analyst,
                                                           "decided_at": _now(), "reason": reason}})

    def rerender(self, env_id: str, shallow: bool = False) -> dict:
        doc = self.get(env_id)
        if doc["status"] != "approved":
            raise ValueError("only an approved environment can be rendered")
        out = render_environment(EnvironmentSpec.model_validate(doc["spec"]), CanaryRegistry(self.db),
                                 self.render_cfg, env_id, self.db, shallow=shallow)
        self.envs.update_one({"env_id": env_id}, {"$set": {"rendered_at": _now()}})
        return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("design")
    d.add_argument("--brief", default="")
    for name in ("show", "render"):
        sub.add_parser(name).add_argument("env_id")
    a = sub.add_parser("approve")
    a.add_argument("env_id")
    a.add_argument("analyst")
    r = sub.add_parser("reject")
    r.add_argument("env_id")
    r.add_argument("analyst")
    r.add_argument("reason")
    args = ap.parse_args(argv)

    from pymongo import MongoClient
    env = os.environ
    db = MongoClient(env.get("MONGO_URI", "mongodb://mongodb:27017/maya")).get_default_database()
    cfg = RenderConfig(Path(env.get("DECEPTION_DIR", "/deception")), Path(env.get("RENDER_DIR", "/render")))
    llm = None
    if args.cmd == "design":
        from reliability.loop import bedrock_call_llm
        llm = bedrock_call_llm(env["BEDROCK_MODEL_ID"], env.get("AWS_REGION", "us-west-2"), max_tokens=8000)
    svc = BuildService(db, cfg, llm, env.get("BEDROCK_MODEL_ID", ""))

    if args.cmd == "design":
        doc = svc.design(args.brief)
        print(f"{doc['env_id']}: {doc['status']} after {doc['attempts']} attempt(s)")
        for e in doc["errors"]:
            print("  error:", e)
        for w in doc["warnings"]:
            print("  warning:", w)
    elif args.cmd == "show":
        print(json.dumps(svc.get(args.env_id), indent=2, default=str))
    elif args.cmd == "approve":
        out = svc.approve(args.env_id, args.analyst)
        print(json.dumps(out, indent=2))
    elif args.cmd == "reject":
        svc.reject(args.env_id, args.analyst, args.reason)
        print("rejected")
    elif args.cmd == "render":
        print(json.dumps(svc.rerender(args.env_id), indent=2))


if __name__ == "__main__":
    sys.exit(main())
