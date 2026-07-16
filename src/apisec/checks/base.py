from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

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


class Check(Protocol):
    """Every check module exposes one of these. `run` gets a live requests
    Session (with any auth already configured) and the Endpoint under test,
    and returns zero or more Findings."""

    id: str
    title: str

    def run(self, endpoint: Endpoint, base_url: str, session: requests.Session) -> list[Finding]:
        ...
