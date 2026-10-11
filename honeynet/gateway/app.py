"""llm-gateway: the attack zone's only route out, and it only reaches Bedrock.

The victim assistant and the attacker agents live on attack-net (no internet). They call:
  POST /converse  {caller, model, messages, system?, toolConfig?, max_tokens?}   -> Bedrock Converse
  POST /embed     {caller, texts}                                                -> embeddings
Enforced here, whatever the caller asks: model allowlist, max_tokens cap, daily calls per
caller and source address, optional Bedrock Guardrail. Every call is logged (sizes and
token counts, never the prompt) for cost and audit. The IAM role is used; no keys.

Run:  uvicorn honeynet.gateway.app:from_env --factory --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

CALLER = re.compile(r"^[a-z][a-z0-9_-]{1,40}$")


def create_app(client, allowed_models: set[str], embed_model: str, max_tokens: int, daily_calls: int,
               log_path: Path, guardrail: tuple[str, str] | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    calls: Counter = Counter()
    log_path = Path(log_path)

    def log(**rec):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "source": "gateway", **rec}) + "\n")

    def admit(request: Request, body: dict, kind: str):
        """-> (caller, ip, error response or None)"""
        caller, ip = str(body.get("caller", "")), request.client.host if request.client else ""
        if not CALLER.match(caller):
            return caller, ip, JSONResponse({"error": "caller name required"}, 400)
        key = (caller, ip, datetime.now(timezone.utc).date().isoformat())
        if calls[key] >= daily_calls:
            log(caller=caller, src_ip=ip, kind=kind, status="refused", reason="daily cap")
            return caller, ip, JSONResponse({"error": "daily call cap reached"}, 429)
        calls[key] += 1
        return caller, ip, None

    @app.get("/health")
    def health():
        return {"ok": True, "models": sorted(allowed_models)}

    @app.post("/converse")
    async def converse(request: Request):
        body = await request.json()
        caller, ip, err = admit(request, body, "converse")
        if err:
            return err
        model = body.get("model")
        if model not in allowed_models:
            log(caller=caller, src_ip=ip, kind="converse", model=model, status="refused", reason="model not allowed")
            return JSONResponse({"error": "model not allowed"}, 403)
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return JSONResponse({"error": "messages required"}, 400)
        req = {"modelId": model, "messages": messages,
               "inferenceConfig": {"maxTokens": min(int(body.get("max_tokens") or max_tokens), max_tokens),
                                   "temperature": float(body.get("temperature", 0.2))}}
        if body.get("system"):
            req["system"] = [{"text": str(body["system"])}]
        if body.get("toolConfig"):
            req["toolConfig"] = body["toolConfig"]
        if guardrail:
            req["guardrailConfig"] = {"guardrailIdentifier": guardrail[0], "guardrailVersion": guardrail[1]}
        try:
            resp = client.converse(**req)
        except Exception as e:                       # Bedrock errors go back to the caller, logged
            log(caller=caller, src_ip=ip, kind="converse", model=model, status="error", error=type(e).__name__)
            return JSONResponse({"error": f"bedrock: {type(e).__name__}"}, 502)
        usage = resp.get("usage", {})
        log(caller=caller, src_ip=ip, kind="converse", model=model, status="ok",
            input_tokens=usage.get("inputTokens"), output_tokens=usage.get("outputTokens"),
            stop_reason=resp.get("stopReason"))
        return {"message": resp["output"]["message"], "stop_reason": resp.get("stopReason"), "usage": usage}

    @app.post("/embed")
    async def embed(request: Request):
        body = await request.json()
        caller, ip, err = admit(request, body, "embed")
        if err:
            return err
        texts = body.get("texts")
        if not isinstance(texts, list) or not texts or len(texts) > 64:
            return JSONResponse({"error": "texts: 1 to 64 strings"}, 400)
        out = []
        for t in texts:
            resp = client.invoke_model(modelId=embed_model, body=json.dumps({"inputText": str(t)[:8000]}))
            out.append(json.loads(resp["body"].read())["embedding"])
        log(caller=caller, src_ip=ip, kind="embed", model=embed_model, status="ok", texts=len(texts))
        return {"embeddings": out}

    return app


def from_env() -> FastAPI:
    """uvicorn --factory entry point (the container)."""
    import boto3
    env = os.environ
    g = (env["GUARDRAIL_ID"], env.get("GUARDRAIL_VERSION") or "DRAFT") if env.get("GUARDRAIL_ID") else None
    return create_app(boto3.client("bedrock-runtime", region_name=env.get("AWS_REGION", "us-west-2")),
                      {m for m in env.get("ALLOWED_MODELS", "").split(",") if m},
                      env.get("EMBED_MODEL", "amazon.titan-embed-text-v2:0"), int(env.get("MAX_TOKENS", "1500")),
                      int(env.get("DAILY_CALLS_PER_CALLER", "400")), Path(env.get("LOG_PATH", "/trap-logs/gateway.jsonl")), g)
