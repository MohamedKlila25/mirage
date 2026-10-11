"""The company MCP tools over a real stdio transport: a subprocess MCP server + the SDK client.

Skipped automatically if no local MongoDB is reachable (the server runs in its own process, so it needs
a real database rather than mongomock). RAG is left off here so the round-trip stays offline."""
import json
import os
import uuid
from pathlib import Path

import pytest

pymongo = pytest.importorskip("pymongo")


def _mongo_or_skip():
    uri = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/maya")
    try:
        c = pymongo.MongoClient(uri, serverSelectionTimeoutMS=800)
        c.admin.command("ping")
        return c, uri
    except Exception:
        pytest.skip("no local MongoDB reachable for the stdio-transport test")


def test_company_tools_over_stdio_transport(tmp_path):
    from ai_traps.mcp_client import StdioMCPCompany
    from ai_traps.mcp_company import DECOY_TOOLS
    client_mongo, uri = _mongo_or_skip()
    dbname = "maya_test_" + uuid.uuid4().hex[:8]
    trap = tmp_path / "mcp.jsonl"
    client = StdioMCPCompany(db_name=dbname, trap_log=trap, src_ip="10.100.0.77",
                             env={"MONGO_URI": uri})
    try:
        tools = client.list_tools()
        assert "search_docs" in tools and "export_all_customers" in tools   # real tool discovery

        r = client.call("victim-assistant", "list_tickets", {})             # real tool
        assert r.ok and "TK-" in r.output

        d = client.call("victim-assistant", "export_all_customers", {})     # decoy tool -> trap_hit
        assert d.ok and "export_all_customers" in " ".join(DECOY_TOOLS)

        s = client.call("victim-assistant", "search_docs", {"query": "customer master list"})
        assert "#" in s.output                                              # documents returned
    finally:
        client.close()
        client_mongo.drop_database(dbname)

    events = [json.loads(l) for l in Path(trap).read_text().splitlines()]
    kinds = {e["event_type"] for e in events}
    assert "trap_hit" in kinds                                              # the decoy call was logged
    assert any(e.get("trap_id") == "mcp:export_all_customers" for e in events)
