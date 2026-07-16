"""API3:2023 - Broken Object Property Level Authorization
(formerly "Excessive Data Exposure" in the 2019 OWASP API list).

STATUS: stub — Week 3-4 task.

Approach:
1. Call the endpoint (GET) and inspect the response JSON body.
2. Flag fields whose *name* looks sensitive (password, token, secret, ssn,
   credit_card, hash, ...) — see SENSITIVE_FIELD_PATTERN below.
3. Cross-check against the OpenAPI response schema: a sensitive field that
   isn't declared in the spec is a strong signal the handler is serializing
   an internal model directly instead of an explicit response DTO.

This one is intentionally heuristic (name-pattern matching), so expect some
false positives — worth adding an allowlist/config file for known-safe
field names once you see real results against the demo API.
"""

from __future__ import annotations

import re

import requests

from apisec.checks.base import Finding, Severity
from apisec.spec_loader import Endpoint

SENSITIVE_FIELD_PATTERN = re.compile(
    r"(password|secret|token|api[_-]?key|ssn|credit[_-]?card|hash)", re.IGNORECASE
)


class ExcessiveDataExposureCheck:
    id = "API3:2023"
    title = "Excessive Data Exposure"

    def run(self, endpoint: Endpoint, base_url: str, session: requests.Session) -> list[Finding]:
        if endpoint.method != "GET":
            return []
        # TODO: implement — see module docstring.
        return []
