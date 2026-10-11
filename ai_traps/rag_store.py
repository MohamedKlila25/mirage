"""A real retrieval layer for the honeynet RAG: Bedrock Titan embeddings + a Chroma vector database.

search_docs() in the company MCP server queries this store, so an attacking agent's document
retrieval is genuine semantic vector search over embedded documents — not keyword matching. Pulling a
restricted honey-doc out of the index is the ASI06 signal. The embedder is injected, so tests run
offline with a deterministic hash embedder; the live wiring uses Bedrock Titan v2 (1024-dim)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable

Embedder = Callable[[list[str]], list[list[float]]]


def bedrock_embedder(region: str = "us-west-2", model_id: str = "amazon.titan-embed-text-v2:0") -> Embedder:
    """Live embeddings via Amazon Titan Text Embeddings v2 on Bedrock."""
    import boto3

    client = boto3.client("bedrock-runtime", region_name=region)

    def embed(texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            resp = client.invoke_model(modelId=model_id, body=json.dumps({"inputText": t[:8000]}))
            out.append(json.loads(resp["body"].read())["embedding"])
        return out

    return embed


def hash_embedder(dim: int = 96) -> Embedder:
    """Deterministic, offline embedder for tests: hashed bag-of-tokens, L2-normalised."""
    def embed(texts: list[str]) -> list[list[float]]:
        vecs = []
        for t in texts:
            v = [0.0] * dim
            for tok in t.lower().split():
                v[int(hashlib.md5(tok.encode()).hexdigest(), 16) % dim] += 1.0
            n = sum(x * x for x in v) ** 0.5 or 1.0
            vecs.append([x / n for x in v])
        return vecs

    return embed


@dataclass
class RagStore:
    """A persistent Chroma collection of documents, embedded with the injected embedder."""
    persist_dir: str
    embed: Embedder
    collection: str = "honeynet_docs"

    def __post_init__(self):
        import chromadb
        from chromadb.config import Settings
        self._client = chromadb.PersistentClient(path=str(self.persist_dir),
                                                 settings=Settings(anonymized_telemetry=False))
        # cosine space; recreate so a changed document set never leaves stale vectors behind
        try:
            self._client.delete_collection(self.collection)
        except Exception:
            pass
        self._col = self._client.get_or_create_collection(self.collection, metadata={"hnsw:space": "cosine"})

    def index(self, docs: dict) -> int:
        """docs: title -> (is_honey, body). Embeds and upserts all of them."""
        ids, texts, metas = [], [], []
        for title, (honey, body) in docs.items():
            ids.append(title)
            texts.append(f"{title}\n{body}")
            metas.append({"title": title, "is_honey": bool(honey), "body": body})
        if not ids:
            return 0
        self._col.upsert(ids=ids, embeddings=self.embed(texts), documents=texts, metadatas=metas)
        return len(ids)

    def search(self, query: str, k: int = 3) -> list[dict]:
        """Top-k documents by cosine similarity. Returns dicts with title/is_honey/body/score."""
        if not (query or "").strip():
            got = self._col.get(include=["metadatas"], limit=k)
            return [{"title": m["title"], "is_honey": m["is_honey"], "body": m["body"], "score": None}
                    for m in (got.get("metadatas") or [])]
        res = self._col.query(query_embeddings=self.embed([query]), n_results=k,
                              include=["metadatas", "distances"])
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        return [{"title": m["title"], "is_honey": m["is_honey"], "body": m["body"],
                 "score": round(1 - d, 3) if d is not None else None}
                for m, d in zip(metas, dists)]
