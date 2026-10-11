"""The shared policy interface: Static, RL (optional) and Agent all decide with the same inputs
and return the same Action shape, and every Action goes through mirage-control. That makes the
static-vs-agent comparison fair: same actions, same checks, different brain.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field

# Every tool mirage-control exposes. "auto" runs at once; "approval" waits for the analyst.
TOOLS: dict[str, str] = {
    "observe": "auto",
    "plant_breadcrumb": "auto",
    "create_wiki_page": "auto",
    "tag_session": "auto",
    "escalate_tier": "approval",
    "open_decoy_service": "approval",
    "recommend_block": "approval",
    "revoke_agent_token": "approval",
    "disable_mcp_tool": "approval",
}
MAX_TIER = 3


@dataclass
class Action:
    tool: str
    params: dict
    reason: str
    evidence: list[str] = field(default_factory=list)
    policy: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionState:
    """What any policy may know about one attacker session. Built by brain/session.py."""
    session_id: str
    events: list[dict] = field(default_factory=list)          # all events so far, oldest first
    tier: int = 1
    planted: list[dict] = field(default_factory=list)         # decoys already planted for this session
    actions: list[dict] = field(default_factory=list)         # earlier actions (any status)
    pending_approvals: list[dict] = field(default_factory=list)

    @property
    def commands(self) -> list[dict]:
        return [e for e in self.events if e.get("event_type") == "command"]

    @property
    def hosts_logged_in(self) -> list[str]:
        seen = []
        for e in self.events:
            if e.get("event_type") == "login" and e.get("host") not in seen:
                seen.append(e["host"])
        return seen

    def already_planted(self, host: str, path: str) -> bool:
        return any(p.get("host") == host and p.get("path") == path for p in self.planted)

    def has_pending(self, tool: str) -> bool:
        return any(a.get("tool") == tool for a in self.pending_approvals)


class Policy(ABC):
    name: str = "base"
    uses_llm: bool = False       # the brain only enforces the LLM budget for policies that call a model
    max_actions: int = 5         # the brain sends at most this many actions per batch to mirage-control

    @abstractmethod
    def decide(self, state: SessionState, new_events: list[dict]) -> list[Action]:
        """Return actions for mirage-control. Must not have side effects of its own."""

    def _act(self, tool: str, params: dict, reason: str, evidence: list[str]) -> Action:
        if tool not in TOOLS:
            raise ValueError(f"unknown tool {tool}")
        return Action(tool, params, reason, evidence, self.name)
