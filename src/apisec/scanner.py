from __future__ import annotations

import requests

from apisec.checks import ALL_CHECKS
from apisec.checks.base import Finding, ScanContext
from apisec.spec_loader import extract_endpoints, load_spec


def scan(
    spec_path: str,
    base_url: str,
    auth_header: str | None = None,
    auth_header_b: str | None = None,
    public_paths: list[str] | None = None,
) -> list[Finding]:
    spec = load_spec(spec_path)
    endpoints = extract_endpoints(spec)

    session_a = requests.Session()
    if auth_header:
        session_a.headers["Authorization"] = auth_header

    session_b = None
    if auth_header_b:
        session_b = requests.Session()
        session_b.headers["Authorization"] = auth_header_b

    ctx = ScanContext(
        base_url=base_url,
        session_a=session_a,
        session_b=session_b,
        public_paths=public_paths or [],
        all_endpoints=endpoints,
    )

    findings: list[Finding] = []
    for endpoint in endpoints:
        for check in ALL_CHECKS:
            findings.extend(check.run(endpoint, ctx))
    return findings
