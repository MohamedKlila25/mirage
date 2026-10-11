"""StaticPolicy: Mirage's original, non-adaptive behaviour. It is the baseline the agent is
compared against, and what takes over when the kill switch is pressed.

  - when an attacker first logs into a decoy: plant that decoy's fixed breadcrumbs
    (the same files for everyone; they come from Mirage's repo, referenced by template name)
  - every `escalate_every` commands: ask to escalate one tier (needs approval), up to tier 3
  - otherwise: observe
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import MAX_TIER, Action, Policy, SessionState


@dataclass
class StaticBreadcrumb:
    host: str
    path: str
    template: str        # name of a file in honeynet/cowrie/static/, taken from Mirage's repo


@dataclass
class StaticConfig:
    breadcrumbs: list[StaticBreadcrumb] = field(default_factory=list)
    escalate_every: int = 15          # commands per tier step (align with Mirage's own tiers)


class StaticPolicy(Policy):
    name = "static"

    def __init__(self, cfg: StaticConfig):
        self.cfg = cfg

    def decide(self, state: SessionState, new_events: list[dict]) -> list[Action]:
        actions: list[Action] = []

        for ev in new_events:
            if ev.get("event_type") != "login":
                continue
            for b in self.cfg.breadcrumbs:
                if b.host == ev.get("host") and not state.already_planted(b.host, b.path) \
                        and not any(a.params.get("path") == b.path and a.params.get("host") == b.host for a in actions):
                    actions.append(self._act("plant_breadcrumb",
                                             {"host": b.host, "path": b.path, "template": b.template},
                                             "static schedule: fixed breadcrumb on first login", [ev["event_id"]]))

        n_cmd = len(state.commands)
        wanted_tier = min(MAX_TIER, 1 + n_cmd // self.cfg.escalate_every) if self.cfg.escalate_every else 1
        if wanted_tier > state.tier and not state.has_pending("escalate_tier"):
            last_cmd = state.commands[-1]["event_id"] if state.commands else None
            actions.append(self._act("escalate_tier", {"session_id": state.session_id, "tier": state.tier + 1},
                                     f"static schedule: {n_cmd} commands reached", [last_cmd] if last_cmd else []))

        if not actions and new_events:
            actions.append(self._act("observe", {"session_id": state.session_id, "note": "static: nothing scheduled"},
                                     "no scheduled action", [new_events[-1]["event_id"]]))
        return actions
