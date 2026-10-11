"""Strict schema for the defender's LLM output.

The LLM must answer with exactly this JSON shape. Anything else (missing evidence,
extra fields, wrong types, malformed technique IDs) is rejected before any action.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EventId = str
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
OWASP_PATTERN = r"^ASI(0[1-9]|10)$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Profile(_Strict):
    actor: Literal["human", "bot", "ai_agent", "unknown"]
    skill: Literal["low", "mid", "high", "unknown"]
    objective: str = Field(min_length=1, max_length=64)  # e.g. data_theft, benign
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EventId] = Field(min_length=1)


class TechniqueClaim(_Strict):
    id: str = Field(pattern=TECHNIQUE_PATTERN)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EventId] = Field(min_length=1)


class OwaspClaim(_Strict):
    id: str = Field(pattern=OWASP_PATTERN)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EventId] = Field(min_length=1)


class Prediction(_Strict):
    technique: str = Field(pattern=TECHNIQUE_PATTERN)
    p: float = Field(ge=0.0, le=1.0)


class ToolCall(_Strict):
    tool: str
    params: dict
    reason: str = Field(min_length=1, max_length=500)
    evidence: list[EventId] = Field(min_length=1)


class Proposal(_Strict):
    type: Literal[
        "sigma_rule", "ioc_block", "hardening",
        "revoke_token", "disable_tool", "quarantine_doc",
    ]
    payload: dict
    technique: str | None = Field(default=None, pattern=TECHNIQUE_PATTERN)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EventId] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=1000)


class Strategy(_Strict):
    session_id: str
    profile: Profile
    attack_techniques: list[TechniqueClaim] = Field(default_factory=list)
    owasp_agentic: list[OwaspClaim] = Field(default_factory=list)
    predicted_next: list[Prediction] = Field(default_factory=list, max_length=3)
    goal: Literal["gather_intel", "slow_down", "contain"]
    honeynet_actions: list[ToolCall] = Field(default_factory=list, max_length=5)
    proposals: list[Proposal] = Field(default_factory=list, max_length=10)


def json_schema_for_prompt() -> dict:
    """Give this to the LLM (Bedrock tool spec / system prompt) so it knows the contract."""
    return Strategy.model_json_schema()
