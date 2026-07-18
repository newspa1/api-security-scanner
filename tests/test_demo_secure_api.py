"""Correctness tests for demo_secure_api -- the control group. Two layers:
(1) the app itself behaves as designed (each fix actually works), and (2)
running the REAL scanner (ALL_CHECKS) against it produces zero findings.
That second layer is the part that actually proves "the scanner doesn't cry
wolf on secure code" as an automated, re-checkable fact, not just a claim.
"""

from __future__ import annotations

import base64
import json

import jwt
import pytest

from apisec.checks import ALL_CHECKS
from apisec.checks.base import ScanContext
from apisec.spec_loader import extract_endpoints
from demo_secure_api.app import SECRET_KEY, _reset_state, app


@pytest.fixture
def secure_app_sessions(sessions_for):
    _reset_state()
    return sessions_for(app, ("alice", "alice-pw"), ("bob", "bob-pw"))


def _forge_alg_none(token: str) -> str:
    payload = jwt.decode(token, options={"verify_signature": False})

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    return f"{header}.{body}."


# ---- the app itself behaves as designed ---------------------------------------

def test_forged_alg_none_token_is_rejected(secure_app_sessions):
    client, (session_a, _) = secure_app_sessions
    real_token = session_a.headers["Authorization"].removeprefix("Bearer ")
    forged = _forge_alg_none(real_token)
    resp = client.get("/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_me_response_has_no_password_fields(secure_app_sessions):
    client, (session_a, _) = secure_app_sessions
    resp = client.get("/me", headers=session_a.headers)
    body = resp.json()
    assert "password" not in body
    assert "password_hash" not in body


def test_bob_cannot_read_alices_order(secure_app_sessions):
    client, (_, session_b) = secure_app_sessions
    resp = client.get("/orders/1", headers=session_b.headers)  # order 1 is Alice's
    assert resp.status_code == 403


def test_patch_me_ignores_undeclared_role_field(secure_app_sessions):
    client, (session_a, _) = secure_app_sessions
    client.patch("/me", headers=session_a.headers, json={"name": "Alice X", "role": "admin"})
    body = client.get("/me", headers=session_a.headers).json()
    assert "role" not in body


# ---- the real scanner, run against this app, finds NOTHING -------------------

def test_full_scan_finds_zero_vulnerabilities(secure_app_sessions):
    client, (session_a, session_b) = secure_app_sessions
    spec = client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)

    findings = [f for ep in endpoints for check in ALL_CHECKS for f in check.run(ep, ctx)]

    assert findings == []
