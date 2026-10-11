"""The real RAG: Chroma vector store + injected embeddings, and the honey-doc retrieval trap through it."""
import json
from pathlib import Path

import mongomock

from ai_traps.mcp_company import MCPCompany
from ai_traps.rag_store import RagStore, hash_embedder
from ai_traps.victim import DOCS


def _store(tmp_path) -> RagStore:
    rag = RagStore(str(tmp_path / "rag"), hash_embedder())
    rag.index(dict(DOCS))
    return rag


def test_vector_search_ranks_relevant_doc_first(tmp_path):
    rag = _store(tmp_path)
    hits = rag.search("customer master list confidential", k=3)
    assert hits and hits[0]["title"].lower().startswith("customer master list")
    assert hits[0]["is_honey"] is True
    assert hits[0]["score"] is not None          # a real similarity score


def test_empty_query_returns_some_docs(tmp_path):
    assert len(_store(tmp_path).search("", k=3)) == 3


def test_mcp_search_through_rag_logs_doc_retrieval(tmp_path):
    db = mongomock.MongoClient().maya
    mcp = MCPCompany(db, tmp_path / "mcp.jsonl", docs=dict(DOCS), rag=_store(tmp_path))
    mcp.call("victim-assistant", "search_docs", {"query": "service account vault admin credentials"})
    events = [json.loads(l) for l in Path(mcp.trap_log).read_text().splitlines()]
    retrievals = [e for e in events if e["event_type"] == "doc_retrieval"]
    assert retrievals and all(e["trap_id"].startswith("rag:") for e in retrievals)


def test_keyword_fallback_when_no_rag(tmp_path):
    db = mongomock.MongoClient().maya
    mcp = MCPCompany(db, tmp_path / "mcp.jsonl", docs=dict(DOCS))   # rag=None
    out = mcp.call("victim-assistant", "search_docs", {"query": "customer"}).output
    assert "#" in out            # still returns documents via keyword fallback
