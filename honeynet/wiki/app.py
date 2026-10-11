"""Fake internal wiki on attack-net. Every request is a trap event (logged for the collector).

Pages are Markdown files written by code only (builder/render.py, mirage-control's create_wiki_page):
  <wiki_dir>/<slug>.md            public
  <wiki_dir>/internal/<slug>.md   shown from tier 2 (control/tiers.json, per attacker session)
No FastAPI docs and no server header: nothing that says "this is a Python lab".

Run:  uvicorn honeynet.wiki.app:from_env --factory --host 0.0.0.0 --port 80
"""
from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

SLUG = re.compile(r"^[a-z0-9-]{1,60}$")


def session_id(ip: str) -> str:
    """Same rule as the collector: one session per attacker source address."""
    return "att-" + "".join(c if c.isalnum() else "-" for c in (ip or "unknown"))


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><html><head><title>{html.escape(title)}</title></head>"
                        f"<body>{body}</body></html>", status_code=status)


def create_app(wiki_dir: Path, control_dir: Path, log_path: Path, site_name: str = "Internal wiki") -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    wiki_dir, control_dir, log_path = Path(wiki_dir), Path(control_dir), Path(log_path)

    def log(request: Request, status: int):
        ua = request.headers.get("user-agent", "")[:120]
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "source": "wiki", "host": "wiki",
               "event_type": "http_request", "src_ip": request.client.host if request.client else "",
               "untrusted_content": f"{request.method} {request.url.path} status={status} ua={ua}"[:500]}
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def tier(request: Request) -> int:
        try:
            tiers = json.loads((control_dir / "tiers.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            tiers = {}
        return int(tiers.get(session_id(request.client.host if request.client else ""), 1))

    def pages(sub: str = "") -> list[str]:
        d = wiki_dir / sub if sub else wiki_dir
        return sorted(p.stem for p in d.glob("*.md")) if d.is_dir() else []

    def show(request: Request, path: Path, title: str) -> HTMLResponse:
        if not path.is_file():
            log(request, 404)
            return _page("Not found", "<h1>Page not found</h1>", 404)
        log(request, 200)
        return _page(title, f"<pre>{html.escape(path.read_text())}</pre>")

    @app.get("/")
    def index(request: Request):
        items = [f'<li><a href="/{p}">{p}</a></li>' for p in pages()]
        if tier(request) >= 2:
            items += [f'<li><a href="/internal/{p}">internal/{p}</a></li>' for p in pages("internal")]
        log(request, 200)
        return _page(site_name, f"<h1>{html.escape(site_name)}</h1><ul>{''.join(items)}</ul>")

    @app.get("/internal/{slug}")
    def internal(slug: str, request: Request):
        if not SLUG.match(slug):
            log(request, 404)
            return _page("Not found", "<h1>Page not found</h1>", 404)
        if tier(request) < 2:
            log(request, 403)
            return _page("Forbidden", "<h1>Restricted space</h1><p>Ask the ops team for access.</p>", 403)
        return show(request, wiki_dir / "internal" / f"{slug}.md", slug)

    @app.get("/{slug}")
    def page(slug: str, request: Request):
        if not SLUG.match(slug):
            log(request, 404)
            return _page("Not found", "<h1>Page not found</h1>", 404)
        return show(request, wiki_dir / f"{slug}.md", slug)

    return app


def from_env() -> FastAPI:
    """uvicorn --factory entry point (the container)."""
    env = os.environ
    return create_app(Path(env.get("WIKI_DIR", "/wiki")), Path(env.get("CONTROL_DIR", "/control")),
                      Path(env.get("LOG_PATH", "/trap-logs/wiki.jsonl")), env.get("WIKI_NAME", "Internal wiki"))
