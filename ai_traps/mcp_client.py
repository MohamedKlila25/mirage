"""A synchronous client for the company MCP server over a real stdio transport.

It spawns `python -m ai_traps.mcp_server` as a subprocess and talks JSON-RPC to it through the MCP SDK,
while presenting the same `.call(agent_id, tool, args) -> ToolResult` interface as the in-process
MCPCompany — so the victim agent loop is identical whichever transport is used. The async MCP session
lives inside one long-running task on a background event loop (so anyio's task groups are entered and
exited on the same task); sync callers hand work to it through a queue."""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import os
import sys
import threading
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ai_traps.mcp_company import ToolResult

REPO = Path(__file__).resolve().parents[1]


class StdioMCPCompany:
    def __init__(self, db_name, trap_log, control_dir=None, src_ip="10.100.0.50", rag_dir=None,
                 env=None, agent_id="victim-assistant", ready_timeout=90):
        self.agent_id = agent_id
        self.inbox, self.docs, self.rag = [], {}, None     # server-owned; set here only to satisfy callers
        sub = dict(os.environ)
        if env:
            sub.update({k: v for k, v in env.items() if v is not None})
        sub["PYTHONPATH"] = str(REPO)
        sub.update({"MONGO_URI": sub.get("MONGO_URI") or os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/maya"),
                    "MCP_DB_NAME": str(db_name), "MCP_TRAP_LOG": str(trap_log), "MCP_SRC_IP": str(src_ip),
                    "MCP_AGENT_ID": agent_id})
        if control_dir:
            sub["MCP_CONTROL_DIR"] = str(control_dir)
        if rag_dir:
            sub["MCP_RAG_DIR"] = str(rag_dir)
        self._params = StdioServerParameters(command=sys.executable, args=["-m", "ai_traps.mcp_server"],
                                             env=sub, cwd=str(REPO))
        self._queue: asyncio.Queue | None = None
        self._ready = cf.Future()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.result(timeout=ready_timeout)          # raises if the server failed to start

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self):
        self._queue = asyncio.Queue()
        try:
            async with stdio_client(self._params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    if not self._ready.done():
                        self._ready.set_result(True)
                    while True:
                        item = await self._queue.get()
                        if item is None:
                            break
                        kind, arg, fut = item
                        try:
                            if kind == "call":
                                fut.set_result(await session.call_tool(arg[0], arg[1]))
                            elif kind == "list":
                                fut.set_result(await session.list_tools())
                        except Exception as e:                # noqa: BLE001
                            fut.set_exception(e)
        except Exception as e:                                # noqa: BLE001
            if not self._ready.done():
                self._ready.set_exception(e)

    def _request(self, kind, arg, timeout=60):
        fut = cf.Future()
        self._loop.call_soon_threadsafe(self._queue.put_nowait, (kind, arg, fut))
        return fut.result(timeout=timeout)

    def call(self, agent_id, tool, args=None) -> ToolResult:
        res = self._request("call", (tool, args or {}))
        text = ""
        for c in (res.content or []):
            text = getattr(c, "text", "") or text
        import json
        try:
            d = json.loads(text)
            return ToolResult(bool(d.get("ok", True)), d.get("output", ""), d.get("blocked", ""))
        except Exception:
            return ToolResult(not getattr(res, "isError", False), text, "")

    def list_tools(self) -> list[str]:
        return [t.name for t in self._request("list", None, timeout=30).tools]

    def close(self):
        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
        except Exception:
            pass
        self._thread.join(timeout=8)
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
        except Exception:
            pass
