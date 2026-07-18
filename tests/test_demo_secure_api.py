"""Correctness tests for demo_apps/secure -- the control group: proves each
individual fix actually works (this file). Whether the REAL scanner agrees
and finds zero findings overall is covered once, alongside the other three
targets, in test_scan_all_targets.py -- no need to duplicate that here.
"""

from __future__ import annotations

import base64
import json

import jwt
import pytest

from demo_apps.secure.app import _reset_state, app


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
