"""Mirage SOC console: FastAPI backend serving the live dashboard, analyst controls, and attack launcher.

Run:  .\console.ps1        (or:  PYTHONPATH=. python -m dashboard.server)
Open: http://127.0.0.1:8600
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dashboard import api

STATIC = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    from local.run import context, run_attack
    ctx = context()
    db, control = ctx.db, ctx.control
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    run_state = {"running": False, "policy": None, "attacker": None, "seed": None, "started": None, "last": None, "error": None}
    lock = threading.Lock()

    @app.get("/api/overview")
    def _overview():
        o = api.overview(db)
        o["run"] = run_state
        return o

    @app.get("/api/sessions")
    def _sessions():
        return {"sessions": api.sessions(db)}

    @app.get("/api/incident/{session_id}")
    def _incident(session_id: str):
        return api.incident(db, session_id)

    @app.get("/api/approvals")
    def _approvals():
        return {"approvals": api.approvals(db)}

    @app.post("/api/approve")
    async def _approve(request: Request):
        b = await request.json()
        try:
            rec = control.decide(b["action_id"], b["decision"], b.get("analyst", "analyst"), b.get("reason", ""))
            return {"ok": True, "status": rec["status"]}
        except (KeyError, ValueError) as e:
            return JSONResponse({"ok": False, "error": str(e)}, 400)

    @app.post("/api/killswitch")
    async def _killswitch(request: Request):
        b = await request.json()
        control.set_kill_switch(bool(b.get("on")), b.get("analyst", "analyst"))
        return {"ok": True, "on": control.kill_switch_on()}

    @app.post("/api/set-policy")
    async def _set_policy(request: Request):
        b = await request.json()
        policy = b.get("policy")
        if policy not in ("static", "agent"):
            return JSONResponse({"ok": False, "error": "policy must be static or agent"}, 400)
        db["control"].update_one({"_id": "active_policy"}, {"$set": {"policy": policy, "by": "console"}}, upsert=True)
        return {"ok": True, "policy": policy}

    @app.post("/api/attack")
    async def _attack(request: Request):
        b = await request.json()
        policy = b.get("policy", "agent")
        attacker = b.get("attacker", "auto")
        seed = int(b.get("seed", 1))
        pace = float(b.get("pace", 0.7))
        with lock:
            if run_state["running"]:
                return JSONResponse({"ok": False, "error": "an attack is already running"}, 409)
            run_state.update(running=True, policy=policy, attacker=attacker, seed=seed, started=time.time(), last=None, error=None)

        def worker():
            try:
                m = run_attack(ctx, policy, seed, pace, attacker)
                run_state["last"] = m
            except Exception as e:  # keep the console alive
                run_state["error"] = f"{type(e).__name__}: {e}"
            finally:
                run_state["running"] = False

        threading.Thread(target=worker, daemon=True).start()
        return {"ok": True}

    @app.post("/api/learn-demo")
    def _learn_demo():
        with lock:
            if run_state["running"]:
                return JSONResponse({"ok": False, "error": "busy"}, 409)
            run_state.update(running=True, attacker="learn-demo", started=time.time(), error=None, learn={"round": 0, "total": 5})

        LIMITS = [4, 8, 12, 16, 20, 24, 28, 32, 38, 44]   # reveal more techniques each round -> smooth coverage climb

        def learn_worker():
            import os
            from brain.learning import reset_learning
            prev_m, prev_l = os.environ.get("MIRAGE_DEFENDER_MODEL"), os.environ.get("MIRAGE_SWEEP_LIMIT")
            os.environ["MIRAGE_DEFENDER_MODEL"] = "us.amazon.nova-micro-v1:0"   # small model: starts weak, leans on memory
            run_state["learn"] = {"round": 0, "total": len(LIMITS)}
            try:
                reset_learning(db)
                for i, lim in enumerate(LIMITS, 1):
                    os.environ["MIRAGE_MEMORY"] = "off" if i == 1 else "on"
                    os.environ["MIRAGE_SWEEP_LIMIT"] = str(lim)
                    run_state["learn"] = {"round": i, "total": len(LIMITS)}
                    run_attack(ctx, "agent", 7, 0.1, "sweep")
            except Exception as e:
                run_state["error"] = f"{type(e).__name__}: {e}"
            finally:
                os.environ["MIRAGE_MEMORY"] = "on"
                for k, v in (("MIRAGE_DEFENDER_MODEL", prev_m), ("MIRAGE_SWEEP_LIMIT", prev_l)):
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
                run_state["running"] = False
                run_state["learn"] = None

        threading.Thread(target=learn_worker, daemon=True).start()
        return {"ok": True}

    @app.post("/api/export")
    def _export():
        from integrations.siem import export_all
        from local.run import REPO
        return {"ok": True, **export_all(db, REPO / "exports")}

    @app.get("/api/report/{session_id}")
    def _report(session_id: str, kind: str = "incident"):
        from integrations.reports import incident_report_md, nis2_draft_md
        md = nis2_draft_md(db, session_id) if kind == "nis2" else incident_report_md(db, session_id)
        return {"ok": True, "kind": kind, "markdown": md}

    @app.post("/api/reset")
    def _reset():
        from local.run import _reset_attack
        if run_state["running"]:
            return JSONResponse({"ok": False, "error": "attack running"}, 409)
        _reset_attack(ctx)
        return {"ok": True}

    @app.get("/")
    def _index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def main():
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=8600, log_level="warning")


if __name__ == "__main__":
    main()
