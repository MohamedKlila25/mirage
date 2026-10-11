"""What agent-written decoy text may contain (plan section 8, "Canary placeholders" and "Secret filter").

The agent writes credentials only as placeholders like {{canary:aws_access_key_1}}; code
replaces them with generated canary values. Anything else that looks like a key, token,
private key or password is refused, so the LLM never invents a secret-looking string and
every credential in a decoy is traceable to a canary_use event.
"""
from __future__ import annotations

import re

KINDS = ("password", "aws_access_key", "aws_secret_key", "api_token", "ssh_key")
PLACEHOLDER = re.compile(r"\{\{\s*canary:([a-z_]+?)_(\d{1,3})\s*\}\}")
ANY_PLACEHOLDER = re.compile(r"\{\{[^{}]*\}\}")

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "api_token": re.compile(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}"
                            r"|\bAIza[0-9A-Za-z_-]{30,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}"),
    "credential_assignment": re.compile(
        r"(?i)(?<![a-z])(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"
        r"(_[a-z]+)*[\"']?[ \t]*[:=][ \t]*[\"']?[^\s\"'{}]{3,}"),           # also DB_PASSWORD=, SECRET_KEY:
    "credential_in_url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@"),
    "high_entropy": re.compile(r"(?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Z])(?=[A-Za-z0-9+/_=-]*[a-z])"
                               r"[A-Za-z0-9+/_=-]{32,}"),
}


def placeholder_errors(text: str) -> list[str]:
    """Every {{...}} must be a well-formed canary placeholder of a known kind."""
    errs = []
    for raw in ANY_PLACEHOLDER.findall(text):
        m = PLACEHOLDER.fullmatch(raw)
        if not m:
            errs.append(f"malformed placeholder {raw[:40]}")
        elif m.group(1) not in KINDS:
            errs.append(f"unknown canary kind '{m.group(1)}' (allowed: {', '.join(KINDS)})")
    return errs


def find_secrets(text: str) -> list[str]:
    """Names of secret-like patterns found in text written by the agent, placeholders excluded."""
    stripped = ANY_PLACEHOLDER.sub("", text)
    return [name for name, rx in SECRET_PATTERNS.items() if rx.search(stripped)]


def content_errors(text: str) -> list[str]:
    errs = placeholder_errors(text)
    hits = find_secrets(text)
    if hits:
        errs.append(f"secret-like text {hits}: credentials must be canary placeholders like {{{{canary:password_1}}}}")
    return errs


def placeholder_ids(text: str) -> list[str]:
    """Canary ids referenced in text, in order, without duplicates."""
    seen: list[str] = []
    for kind, n in PLACEHOLDER.findall(text):
        cid = f"{kind}_{int(n)}"
        if cid not in seen:
            seen.append(cid)
    return seen
