"""Strict schema for the adaptive agent's per-batch output (plan section 8).

The LLM must answer with exactly this shape: a profile, its top-3 predicted next techniques,
a goal, and up to 3 actions to take through mirage-control. Anything else (extra fields, bad
technique ids, an unknown tool) is rejected before any action is attempted.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from brain.policies.base import TOOLS

TECHNIQUE = r"^T\d{4}(\.\d{3})?$"
ToolName = Literal[tuple(TOOLS)]  # type: ignore[valid-type]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Profile(_Strict):
    actor: Literal["human", "bot", "ai_agent", "unknown"]
    skill: Literal["low", "mid", "high", "unknown"]
    objective: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)


class Prediction(_Strict):
    technique: str = Field(pattern=TECHNIQUE)
    p: float = Field(ge=0.0, le=1.0)


class ActionCall(_Strict):
    tool: ToolName
    params: dict
    reason: str = Field(min_length=1, max_length=500)
    evidence: list[str] = Field(min_length=1)


class Claim(_Strict):
    text: str = Field(min_length=1, max_length=300)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(min_length=1)


class AgentOutput(_Strict):
    profile: Profile
    predicted_next: list[Prediction] = Field(default_factory=list, max_length=3)
    goal: Literal["gather_intel", "slow_down", "contain"]
    actions: list[ActionCall] = Field(default_factory=list, max_length=3)
    summary: list[Claim] = Field(default_factory=list, max_length=6)   # analyst summary, each claim cites events


def json_schema_for_prompt() -> dict:
    return AgentOutput.model_json_schema()
