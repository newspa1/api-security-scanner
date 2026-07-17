from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import urljoin

import requests

from apisec.spec_loader import Endpoint


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    endpoint: str
    method: str
    description: str
    evidence: str = ""


@dataclass
class ScanContext:
    """Everything a check needs to probe an endpoint. `session_a` is always
    present (the scanner's primary identity); `session_b` is only set when the
    caller supplied a second set of credentials (`--auth-header-b`), which is
    what BOLA needs to compare cross-user access. Checks that don't need a
    second identity simply ignore `session_b`."""

    base_url: str
    session_a: requests.Session
    session_b: requests.Session | None = None


class Check(Protocol):
    """Every check module exposes one of these. `run` gets the Endpoint under
    test and a ScanContext (base URL + one or two authenticated sessions), and
    returns zero or more Findings."""

    id: str
    title: str

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        ...


def concrete_url(path: str, base_url: str, value: str = "1") -> str:
    """Substitute a placeholder for every `{...}` path parameter so e.g.
    `/users/{id}` becomes a requestable URL, then join with base_url. Assumes
    numeric-style auto-increment ids; won't produce a valid id for UUID-keyed
    resources — see bola.py's docstring for that follow-up."""
    concrete_path = re.sub(r"\{[^}]+\}", value, path)
    return urljoin(base_url.rstrip("/") + "/", concrete_path.lstrip("/"))
