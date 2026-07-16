from __future__ import annotations

import requests

from apisec.checks import ALL_CHECKS
from apisec.checks.base import Finding
from apisec.spec_loader import extract_endpoints, load_spec


def scan(spec_path: str, base_url: str, auth_header: str | None = None) -> list[Finding]:
    spec = load_spec(spec_path)
    endpoints = extract_endpoints(spec)

    session = requests.Session()
    if auth_header:
        session.headers["Authorization"] = auth_header

    findings: list[Finding] = []
    for endpoint in endpoints:
        for check in ALL_CHECKS:
            findings.extend(check.run(endpoint, base_url, session))
    return findings
