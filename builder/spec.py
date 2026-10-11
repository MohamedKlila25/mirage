"""What the defender (build mode) is allowed to design.

The agent designs the whole decoy environment: company, hosts, users, which credentials
exist and where, file and wiki contents. It never writes credential values: those are
canary placeholders like {{canary:password_1}} that code fills in (canary/registry.py).
It never writes Docker settings, ports or network config: the three decoy slots are fixed
in docker-compose.yml and code renders everything (render.py) after an analyst approves.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

HOSTNAME = r"^[a-z][a-z0-9-]{2,30}$"
USERNAME = r"^[a-z_][a-z0-9_-]{1,31}$"
SAFE_PATH = r"^/[A-Za-z0-9_./-]{1,120}$"
PASSWORD_PLACEHOLDER = r"^\{\{canary:password_\d{1,3}\}\}$"
SLOTS = ("fake-jump-01", "fake-db-01", "fake-ftp-01")        # docker-compose service names


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserSpec(_Strict):
    username: str = Field(pattern=USERNAME)
    weak_password: bool  # True: code picks a guessable password (entry point)
    canary_password: str | None = Field(default=None, pattern=PASSWORD_PLACEHOLDER)  # login with a planted credential


class BreadcrumbSpec(_Strict):
    path: str = Field(pattern=SAFE_PATH)
    kind: Literal["env_file", "credentials_note", "ssh_config", "db_dump", "wiki_note"]
    points_to: str | None = Field(default=None, pattern=HOSTNAME)  # another decoy = lateral path
    owner: str | None = Field(default=None, pattern=USERNAME)
    content: str | None = Field(default=None, max_length=4096)    # agent-written; credentials as placeholders


class DecoySpec(_Strict):
    hostname: str = Field(pattern=HOSTNAME)                        # what the attacker sees and connects to
    role: Literal["jump", "web", "db", "app", "ftp", "backup"]
    slot: Literal["fake-jump-01", "fake-db-01", "fake-ftp-01"] | None = None
    users: list[UserSpec] = Field(min_length=1, max_length=4)
    breadcrumbs: list[BreadcrumbSpec] = Field(default_factory=list, max_length=6)
    spare_paths: list[str] = Field(default_factory=list, max_length=6)   # empty files the agent may fill later


class ToolSpec(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,40}$")
    description: str = Field(min_length=5, max_length=200)


class DocSpec(_Strict):
    title: str = Field(min_length=3, max_length=80)
    kind: Literal["customer_list", "credentials", "financials", "hr", "strategy"]


class EmployeeSpec(_Strict):
    full_name: str = Field(min_length=3, max_length=60)
    username: str = Field(pattern=USERNAME)
    title: str = Field(min_length=2, max_length=60)


class WikiPageSpec(_Strict):
    title: str = Field(min_length=3, max_length=80)
    markdown: str = Field(min_length=1, max_length=8192)
    section: Literal["public", "internal"] = "public"              # internal = unlocked at tier 2


class EnvironmentSpec(_Strict):
    company: str = Field(min_length=2, max_length=80)
    sector: str = Field(min_length=2, max_length=40)
    product: str | None = Field(default=None, max_length=80)
    stack: list[str] = Field(default_factory=list, max_length=8)
    employees: list[EmployeeSpec] = Field(default_factory=list, max_length=8)
    decoys: list[DecoySpec] = Field(min_length=1, max_length=6)
    wiki_pages: list[WikiPageSpec] = Field(default_factory=list, max_length=8)
    mcp_decoy_tools: list[ToolSpec] = Field(default_factory=list, max_length=6)
    honey_docs: list[DocSpec] = Field(default_factory=list, max_length=5)
    canary_keys: int = Field(default=0, ge=0, le=5)
