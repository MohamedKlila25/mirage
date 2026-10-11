"""mirage-control as an MCP server (MCP Python SDK 2.x: MCPServer, formerly FastMCP).

The agent's ONLY tools. Each tool forwards to MirageControl.call(), which applies every check
and records the call. The agent's identity (policy="agent") is fixed here, not chosen by the model.

Run:  python -m control.server        (streamable HTTP on 0.0.0.0:8100, defense-net only)
"""
from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from .core import ControlConfig, MirageControl


def build_server(control: MirageControl) -> MCPServer:
    mcp = MCPServer("mirage-control", instructions="Restricted honeynet actions. Every call needs a reason and evidence event ids.")

    def call(tool, params, reason, evidence, session_id, batch_id):
        return control.call(tool, params, reason, evidence, "agent", session_id, batch_id)

    @mcp.tool()
    def observe(session_id: str, note: str, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Do nothing; record why."""
        return call("observe", {"session_id": session_id, "note": note}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def plant_breadcrumb(session_id: str, host: str, path: str, reason: str, evidence: list[str],
                         template: str = "", content: str = "", batch_id: str = "") -> dict:
        """Write a breadcrumb file on a decoy: your own content (credentials only as placeholders like
        {{canary:password_1}}) or a template name. Only paths in the decoy's filesystem are accepted."""
        params = {"host": host, "path": path}
        if template:
            params["template"] = template
        if content:
            params["content"] = content
        return call("plant_breadcrumb", params, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def create_wiki_page(session_id: str, title: str, markdown: str, reason: str, evidence: list[str],
                         batch_id: str = "") -> dict:
        """Add a page to the fake internal wiki. Links only to world-model hosts."""
        return call("create_wiki_page", {"title": title, "markdown": markdown}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def tag_session(session_id: str, actor: str, objective: str, techniques: list[str], reason: str,
                    evidence: list[str], batch_id: str = "") -> dict:
        """Store the attacker profile for the dashboard."""
        return call("tag_session", {"session_id": session_id, "actor": actor, "objective": objective,
                                    "techniques": techniques}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def escalate_tier(session_id: str, tier: int, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Ask to unlock the next tier. Needs analyst approval."""
        return call("escalate_tier", {"session_id": session_id, "tier": tier}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def open_decoy_service(session_id: str, name: str, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Ask to enable a predefined decoy. Needs analyst approval."""
        return call("open_decoy_service", {"name": name}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def recommend_block(session_id: str, ioc: str, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Ask to export an IOC for blocking. Needs analyst approval."""
        return call("recommend_block", {"ioc": ioc}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def revoke_agent_token(session_id: str, agent_id: str, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Ask to revoke a company agent's token. Needs analyst approval."""
        return call("revoke_agent_token", {"agent_id": agent_id}, reason, evidence, session_id, batch_id)

    @mcp.tool()
    def disable_mcp_tool(session_id: str, tool_name: str, reason: str, evidence: list[str], batch_id: str = "") -> dict:
        """Ask to disable a company MCP tool. Needs analyst approval."""
        return call("disable_mcp_tool", {"tool_name": tool_name}, reason, evidence, session_id, batch_id)

    return mcp


def main():
    from pymongo import MongoClient
    from reliability.audit import AuditLog

    env = os.environ
    db = MongoClient(env.get("MONGO_URI", "mongodb://mongodb:27017/maya")).get_default_database()
    cfg = ControlConfig(deception_dir=Path(env.get("DECEPTION_DIR", "/deception")),
                        control_dir=Path(env.get("CONTROL_DIR", "/control")),
                        templates_dir=Path(env.get("TEMPLATES_DIR", "/templates")),
                        exports_dir=Path(env.get("EXPORTS_DIR", "/exports")),
                        manifest_path=Path(env["MANIFEST_PATH"]) if env.get("MANIFEST_PATH") else None,
                        render_dir=Path(env["RENDER_DIR"]) if env.get("RENDER_DIR") else None)
    control = MirageControl(db, cfg, AuditLog(env.get("AUDIT_PATH", "/audit/control.jsonl")))
    build_server(control).run(transport="streamable-http", host="0.0.0.0", port=int(env.get("PORT", "8100")))


if __name__ == "__main__":
    main()
