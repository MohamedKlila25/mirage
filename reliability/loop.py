"""One defender batch: prompt -> LLM -> gate, with exactly one retry on invalid output.

`call_llm(system, user) -> str` is injected so the loop is testable without AWS.
Use `bedrock_call_llm` in production (Bedrock Converse via the EC2 IAM role, no keys).
"""
from __future__ import annotations

from typing import Callable

from .pipeline import GateResult, ReliabilityGate, build_prompt

LLM = Callable[[str, str], str]


def run_defender_batch(gate: ReliabilityGate, session_id: str, events: list[dict],
                       call_llm: LLM, memory_notes: str = "") -> GateResult:
    system, user = build_prompt(events, memory_notes, session_id)
    result = gate.process(session_id, events, call_llm(system, user))
    if result.status == "invalid_output":
        result = gate.process(session_id, events, call_llm(system, user + "\n\n" + result.retry_hint))
    return result


def bedrock_call_llm(model_id: str, region: str = "us-west-2", max_tokens: int = 4000,
                     read_timeout: float = 90.0) -> LLM:
    """Returns a call_llm backed by Amazon Bedrock. Credentials come from the IAM role (or, locally,
    the environment). A bounded read timeout so a slow call fails instead of hanging the loop."""
    import boto3  # imported here so tests don't need it
    from botocore.config import Config

    client = boto3.client("bedrock-runtime", region_name=region,
                          config=Config(connect_timeout=10, read_timeout=read_timeout,
                                        retries={"max_attempts": 2, "mode": "standard"}))

    def call(system: str, user: str) -> str:
        resp = client.converse(
            modelId=model_id,
            system=[{"text": system}],
            messages=[{"role": "user", "content": [{"text": user}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
        )
        return "".join(part.get("text", "") for part in resp["output"]["message"]["content"])

    return call
